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
from hloc.db_utils import recreate_db, create_session_for_process
from hloc.models import Domain, DomainType, DomainLabel
from hloc.domain_processing_helper.domain_name_preprocessing import RegexStrategy, \
    preprocess_domains
from hloc.models.domain import domain_to_label_table

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
    parser.add_argument('-b', '--buffer-lines-per-process', type=int, default=1000,
                        help='Number of lines buffered for each process')
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

    finished_reading_event = mp.Event()

    line_queue = mp.Queue(args.number_processes * args.buffer_lines_per_process)
    line_thread = threading.Thread(target=read_file,
                                   args=(args.filepath, line_queue, finished_reading_event),
                                   name='file-reader')
    line_thread.start()
    time.sleep(1)

    stop_event = threading.Event()
    domain_label_queue = mp.Queue()
    domain_label_handle_thread = threading.Thread(target=handle_labels,
                                                  args=(domain_label_queue, stop_event),
                                                  name='domain-label-handler')
    domain_label_handle_thread.start()

    for i in range(0, args.number_processes):
        process = mp.Process(target=preprocess_file_part,
                             args=(args.filepath, i, line_queue, args.ip_version,
                                   args.isp_ip_filter, regex_strategy, tlds, whitelist, parsed_ips,
                                   parsed_ips_lock, domain_label_queue, finished_reading_event),
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

    stop_event.set()
    domain_label_handle_thread.join()
    domain_label_queue.join_thread()

    whitelisted_not_parsed_as_correct = set(parsed_ips) - parsed_ips

    if whitelisted_not_parsed_as_correct:
        ips_missing = ',\n'.join(whitelisted_not_parsed_as_correct)
        logger.warning('IP addresses in whitelist but not parsed: \n{}'.format(ips_missing))

    end = time.time()
    logger.info('Running time: {0}'.format((end - start)))


def read_file(filepath: str, line_queue: mp.Queue, finished_reading_event: mp.Event):
    with open(filepath, encoding='ISO-8859-1') as rdns_file_handle:
        for line in rdns_file_handle:
            try:
                line_queue.put(line)
            except queue.Full:
                time.sleep(0.5)

    line_queue.close()
    finished_reading_event.set()


def handle_labels(labels_queue: mp.Queue, stop_event: threading.Event):
    """Handels the label results and saves them to the database not blocking the other db queries"""

    class DomainLabelHolder:
        def __init__(self, label):
            self.label = label
            self.label_id = 0
            self.domain_ids = []
            self._handled_domain_ids = []

        def add_domain_id(self, domain_id):
            if domain_id not in self.domain_ids and domain_id not in self._handled_domain_ids:
                self.domain_ids.append(domain_id)

        def get_insert_values(self):
            values = [{'domain_id': domain_id, 'domain_label_id': self.label_id}
                      for domain_id in self.domain_ids]
            return values

        def handled_domain_ids(self):
            self._handled_domain_ids.extend(self.domain_ids)
            self.domain_ids.clear()

    def save_labels(domain_labels_dct, new_labels, db_sess):
        if new_labels:
            db_session.commit()
            for label_obj in new_labels:
                label_obj.label_id = label_obj.label.id


        values_to_insert = []
        for label_obj in new_labels:
            if label_obj.domain_ids:
                values_to_insert.extend(label_obj.get_insert_values())
                label_obj.handled_domain_ids()

        insert_expr = domain_to_label_table.insert().values(values_to_insert)
        new_labels.clear()
        db_sess.execute(insert_expr)
        db_sess.commit()

    Session = create_session_for_process()
    db_session = Session()

    new_labels = []
    domain_labels = {}
    counter = 0

    while not stop_event.is_set() or not labels_queue.empty():
        try:
            label_name, domain_id = labels_queue.get(timeout=1)
            try:
                label = domain_labels[label_name]
            except KeyError:
                label_obj = DomainLabel(label_name)
                db_session.add(label_obj)
                label = DomainLabelHolder(label_obj)
                domain_labels[label_name] = label

            new_labels.append(label)
            label.add_domain_id(domain_id)

            counter += 1
            if counter >= 10**4:
                logger.debug('saving')
                save_labels(domain_labels, new_labels, db_session)
                counter = 0

        except queue.Empty:
            pass

    labels_queue.close()
    logger.info('stopped')
    save_labels(domain_labels, new_labels, db_session)


def preprocess_file_part(filepath: str, pnr: int, line_queue: mp.Queue, ip_version: str,
                         ip_encoding_filter: bool, regex_strategy: RegexStrategy,
                         tlds: typing.Set[str], whitelist: typing.Set[str],
                         parsed_ips: typing.Set[str], parsed_ips_lock: mp.Lock,
                         domain_label_queue: mp.Queue, finished_reading_event: mp.Event):
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

        while not finished_reading_event.is_set() or not line_queue.empty():
            try:
                line = line_queue.get(timeout=2)
            except queue.Empty:
                time.sleep(1)
                continue

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
                whitelist, db_session, domain_label_queue)
            count_good_lines += n_good_lines_count
            count_isp_lines += n_ip_lines_count

            db_session.commit()
        else:
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
                    whitelist: typing.Set[str], db_session,
                    domain_labels_queue: mp.Queue) -> (int, int):
    is_ipv6 = ip_version == constants.IPV6_IDENTIFIER

    (good_lines, bad_lines, bad_tld_lines, ip_encoded_lines, custom_filter_lines,
     bad_characters_part) = preprocess_domains([(ip, domain)], tlds, whitelist,
                                               ip_version, regex_strategy,
                                               ip_encoding_filter)

    domain = None

    if good_lines:
        ip_address, domain_address = good_lines[0]
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.valid

    if bad_lines:
        ip_address, domain_address = bad_lines[0]
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.invalid_characters

    if bad_tld_lines:
        ip_address, domain_address = bad_tld_lines[0]
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.bad_tld

    if ip_encoded_lines:
        ip_address, domain_address = ip_encoded_lines[0]
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.ip_encoded

    if custom_filter_lines:
        ip_address, domain_address = custom_filter_lines[0]
        if is_ipv6:
            domain = Domain(domain_address, ipv6_address=ip_address)
        else:
            domain = Domain(domain_address, ipv4_address=ip_address)

        domain.classification_type = DomainType.blacklisted

    db_session.add(domain)
    db_session.commit()
    add_lables_to_domain(domain, domain_labels_queue)

    return len(good_lines), len(ip_encoded_lines)


def add_lables_to_domain(domain: Domain, domain_labels_queue: mp.Queue):
    for label in domain.name.split('.')[::-1]:
        domain_labels_queue.put((label, domain.id))


if __name__ == '__main__':
    main()
