#!/usr/bin/env python3
"""
sanitizing and classification of the domain names

 Merge into ipdns_parser -- important: give alarm if target IP not found in IP2DNS file
"""
import collections
import json
import multiprocessing as mp
import time
import typing
import os

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

    processes = []
    parsed_ips = set()
    parsed_ips_lock = mp.Lock()

    for i in range(0, args.number_processes):
        process = mp.Process(target=preprocess_file_part,
                             args=(args.filepath, i, args.ip_version, args.number_processes,
                                   args.isp_ip_filter, regex_strategy, tlds, whitelist, parsed_ips,
                                   parsed_ips_lock),
                             name='preprocessing_{}'.format(i))
        processes.append(process)
        process.start()

    alive = len(processes)
    while alive > 0:
        try:
            for process in processes:
                process.join()
            process_sts = [pro.is_alive() for pro in processes]
            if process_sts.count(True) != alive:
                logger.info('{} processes alive'.format(process_sts.count(True)))
                alive = process_sts.count(True)
        except KeyboardInterrupt:
            pass

    whitelisted_not_parsed_as_correct = set(parsed_ips) - parsed_ips

    if whitelisted_not_parsed_as_correct:
        ips_missing = ',\n'.join(whitelisted_not_parsed_as_correct)
        logger.warning('IP addresses in whitelist but not parsed: \n{}'.format(ips_missing))

    end = time.time()
    logger.info('Running time: {0}'.format((end - start)))


def preprocess_file_part(filepath: str, pnr: int, ip_version: str, number_processes: int,
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
        with open(filepath, encoding='ISO-8859-1') as rdns_file_handle:
            def line_blocks():
                lines = []
                seek_before = 0
                seek_after = 0

                def prepare():
                    nonlocal seek_before
                    nonlocal seek_after
                    nonlocal lines
                    seek_before = BLOCK_SIZE * pnr
                    seek_after = BLOCK_SIZE * number_processes - BLOCK_SIZE * (pnr + 1)
                    del lines[:]

                prepare()

                for seek_line in rdns_file_handle:
                    if seek_after == 0 and seek_before == 0 and len(lines) >= BLOCK_SIZE:
                        prepare()
                    if seek_before > 0:
                        seek_before -= 1
                    elif len(lines) < BLOCK_SIZE:
                        lines.append(seek_line)
                    elif seek_after > 0:
                        seek_after -= 1
                    if seek_after == 0 and len(lines) >= BLOCK_SIZE:
                        yield lines
                if lines:
                    yield lines

            bad_characters = collections.defaultdict(int)
            count_good_lines = 0
            count_isp_lines = 0

            file_line_blocks = line_blocks()
            ip_domain_list = []
            for line_block in file_line_blocks:
                for line in line_block:
                    if len(line) == 0:
                        continue
                    line = line.strip()
                    ip, domain = line.split(',', 1)
                    ip_domain_list.append((ip, domain))

                    with parsed_ips_lock:
                        parsed_ips.add(ip)

                if len(ip_domain_list) > 10**4:
                    classify_domains(ip_domain_list, ip_version, ip_encoding_filter, regex_strategy,
                                     tlds, whitelist, db_session)
                    db_session.commit()
                    del ip_domain_list[:]

            classify_domains(ip_domain_list, ip_version, ip_encoding_filter, regex_strategy,
                             tlds, whitelist, db_session)
            db_session.commit()

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


def classify_domains(ip_domain_list, ip_version: str, ip_encoding_filter: bool,
                     regex_strategy: RegexStrategy, tlds: typing.Set[str],
                     whitelist: typing.Set[str], db_session):
    is_ipv6 = ip_version == constants.IPV6_IDENTIFIER

    (good_lines, bad_lines, bad_tld_lines, ip_encoded_lines, custom_filter_lines,
     bad_characters_part) = preprocess_domains(ip_domain_list, tlds, whitelist,
                                               ip_version, regex_strategy,
                                               ip_encoding_filter)

    logger.debug('good: {} bad: {} bad dns: {} ip: {} bad chars: {} custom filter {}'
                 .format(len(good_lines), len(bad_lines), len(bad_tld_lines),
                         len(ip_encoded_lines), len(bad_characters_part),
                         len(custom_filter_lines)))

    for ip_address, domain_address in good_lines:
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.valid
        add_labels_to_domain(domain, db_session)
        db_session.add(domain)

    for ip_address, domain_address in bad_lines:
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.invalid_characters
        add_labels_to_domain(domain, db_session)
        db_session.add(domain)

    for ip_address, domain_address in bad_tld_lines:
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.bad_tld
        add_labels_to_domain(domain, db_session)
        db_session.add(domain)

    for ip_address, domain_address in ip_encoded_lines:
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.ip_encoded
        add_labels_to_domain(domain, db_session)
        db_session.add(domain)

    for ip_address, domain_address in custom_filter_lines:
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.blacklisted
        add_labels_to_domain(domain, db_session)
        db_session.add(domain)


if __name__ == '__main__':
    main()
