#!/usr/bin/env python3
"""
sanitizing and classification of the domain names

 Merge into ipdns_parser -- important: give alarm if target IP not found in IP2DNS file
"""
import collections
import json
import multiprocessing as mp
import threading
import time
import typing
import os
import queue

import configargparse

import hloc.constants as constants
from hloc import util
from hloc.db_utils import add_labels_to_domain, recreate_db, create_session_for_process
from hloc.models import Domain, DomainType
from hloc.domain_processing_helper.domain_name_preprocessing import RegexStrategy, \
    preprocess_domains

logger = None
BLOCK_SIZE = 10


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('filepath', type=str, help='The path to the rDNS file to parse')
    parser.add_argument('-p', '--number-processes', type=int, default=4,
                        help='specify the number of processes used')
    parser.add_argument('-t', '--tlds-file', type=str, required=True,
                        help='Set the path to the tlds file')
    parser.add_argument('-i', '--isp-ip-filter', action='store_true',
                        help='set if you want to filter isp ip domain names')
    parser.add_argument('-s', '--regex-strategy', type=str, choices=RegexStrategy.all_values(),
                        default=RegexStrategy.abstract.value, help='Specify a regex Strategy')
    parser.add_argument('-v', '--ip-version', type=str, required=True,
                        choices=[constants.IPV4_IDENTIFIER, constants.IPV6_IDENTIFIER],
                        help='specify the ipVersion')
    parser.add_argument('-f', '--white-list-file-path', type=str,
                        help='path to a file with a white list of IPs')
    parser.add_argument('-l', '--logging-file', type=str, default='preprocess.log',
                        help='Specify a logging file where the log should be saved')
    parser.add_argument('-d', '--database-recreate', action='store_true',
                        help='Recreates the database structure. Attention deletes all data!')
    # parser.add_argument('-c', '--config-file', type=str, dest='config_filepath',
    #                     is_config_file=True, help='The path to a config file')


def main():
    parser = configargparse.ArgParser(default_config_files=['ipdns_default.ini'])

    __create_parser_arguments(parser)
    args = parser.parse_args()

    start = time.time()

    global logger
    logger = util.setup_logger(args.logging_file, 'process')

    if args.database_recreate:
        inp = input('Do you really want to recreate the database structure? (y)')
        if inp == 'y':
            recreate_db()

    if args.isp_ip_filter:
        logger.info('using strategy: {}'.format(args.regex_strategy))
    else:
        logger.info('processing without ip filtering')

    regex_strategy = RegexStrategy(value=args.regex_strategy)

    tlds = set()
    with open(args.tlds_file) as tldFile:
        for line in tldFile:
            line = line.strip()
            if line[0] != '#':
                tlds.add(line.lower())

    whitelist = set()
    if args.white_list_file_path:
        with open(args.white_list_file_path) as filter_list_file:
            for line in filter_list_file:
                whitelist.add(line.strip())
    else:
        whitelist = None

    processes = []
    parsed_ips = set()
    parsed_ips_lock = mp.Lock()

    line_queue = mp.Queue(args.number_processes * 30)
    line_thread = threading.Thread(target=read_file, args=(args.filepath, line_queue))
    line_thread.start()

    for i in range(0, args.number_processes):
        process = mp.Process(target=preprocess_file_part,
                             args=(args.filepath, i, line_queue, args.ip_version,
                                   args.isp_ip_filter, regex_strategy, tlds, whitelist, parsed_ips,
                                   parsed_ips_lock),
                             name='preprocessing_{}'.format(i))
        processes.append(process)
        process.start()

    line_thread.join()
    line_queue.join_thread()
    alive = len(processes)
    while alive > 0:
        try:
            for process in processes:
                process.join()
            process_sts = [pro.is_alive() for pro in processes]
            if process_sts.count(True) != alive:
                logger.debug('{} processes alive'.format(process_sts.count(True)))
                alive = process_sts.count(True)
        except KeyboardInterrupt:
            pass

    whitelisted_not_parsed_as_correct = set(parsed_ips) - parsed_ips

    if whitelisted_not_parsed_as_correct:
        ips_missing = ',\n'.join(whitelisted_not_parsed_as_correct)
        logger.warning('IP addresses in whitelist but not parsed: \n{}'.format(ips_missing))

    end = time.time()
    logger.info('Running time: {0}'.format((end - start)))


def read_file(filepath: str, line_queue: mp.Queue):
    with open(filepath, encoding='ISO-8859-1') as rdns_file_handle:
        for line in rdns_file_handle:
            line_queue.put(line)

    line_queue.close()


def preprocess_file_part(filepath: str, pnr: int, line_queue: mp.Queue, ip_version: str,
                         ip_encoding_filter: bool, regex_strategy: RegexStrategy,
                         tlds: typing.Set[str], whitelist: typing.Set[str],
                         parsed_ips: typing.Set[str], parsed_ips_lock: mp.Lock):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """
    logger.info('starting')
    label_stats = collections.defaultdict(int)

    Session = create_session_for_process()
    db_session = Session()
    try:
        bad_characters = collections.defaultdict(int)
        count_good_lines = 0
        count_isp_lines = 0

        try:
            while not line_queue.empty():
                line = line_queue.get(timeout=2)
                if len(line) == 0:
                    continue
                line = line.strip()
                ip, domain = line.split(',', 1)

                if not domain:
                    logger.info('Warning found empty domain for IP {} skipping'.format(ip))
                    continue

                with parsed_ips_lock:
                    parsed_ips.add(ip)

                n_good_lines_count, n_ip_lines_count = classify_domain(
                    ip, domain, ip_version, ip_encoding_filter, regex_strategy, tlds,
                    whitelist, db_session)
                count_good_lines += n_good_lines_count
                count_isp_lines += n_ip_lines_count

                db_session.commit()
            else:
                logger.info('finished no more lines')
        except queue.Empty:
            logger.info('finished no more lines')

        directory = os.path.dirname(filepath)
        filename = util.get_path_filename(filepath)

        logger.info('good lines: {} ips lines: {}'.format(count_good_lines, count_isp_lines))
        with open(os.path.join(directory, '{0}-{1}-character.stats'.format(filename, pnr)),
                  'w', encoding='utf-8') as characterStatsFile:
            json.dump(bad_characters, characterStatsFile)

        with open(os.path.join(directory, '{0}-{1}-domain-label.stats'.format(filename, pnr)),
                  'w', encoding='utf-8') as labelStatFile:
            json.dump(label_stats, labelStatFile)
    finally:
        db_session.close()
        Session.remove()


def classify_domain(ip: str, domain: str, ip_version: str, ip_encoding_filter: bool,
                    regex_strategy: RegexStrategy, tlds: typing.Set[str],
                    whitelist: typing.Set[str], db_session) -> (int, int):
    is_ipv6 = ip_version == constants.IPV6_IDENTIFIER

    (good_lines, bad_lines, bad_tld_lines, ip_encoded_lines, custom_filter_lines,
     bad_characters_part) = preprocess_domains([(ip, domain)], tlds, whitelist,
                                               ip_version, regex_strategy,
                                               ip_encoding_filter)

    if good_lines:
        ip_address, domain_address = good_lines[0]
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.valid
        add_labels_to_domain(domain, db_session)
        db_session.add(domain)

    if bad_lines:
        ip_address, domain_address = bad_lines[0]
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.invalid_characters
        add_labels_to_domain(domain, db_session)
        db_session.add(domain)

    if bad_tld_lines:
        ip_address, domain_address = bad_tld_lines[0]
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.bad_tld
        add_labels_to_domain(domain, db_session)
        db_session.add(domain)

    if ip_encoded_lines:
        ip_address, domain_address = ip_encoded_lines[0]
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.ip_encoded
        add_labels_to_domain(domain, db_session)
        db_session.add(domain)

    if custom_filter_lines:
        ip_address, domain_address = custom_filter_lines[0]
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.blacklisted
        add_labels_to_domain(domain, db_session)
        db_session.add(domain)

    return len(good_lines), len(ip_encoded_lines)


if __name__ == '__main__':
    main()
