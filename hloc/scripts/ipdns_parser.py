#!/usr/bin/env python3
"""
sanitizing and classification of the domain names

 Merge into ipdns_parser -- important: give alarm if target IP not found in IP2DNS file
"""
import cProfile
import collections
import json
import multiprocessing as mp
import os
import re
import time

import configargparse
import marisa_trie

from hloc import util
from hloc.util import Domain

logger = None


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('filename', help='filename to sanitize', type=str)

    parser.add_argument('-n', '--num-processes', type=int,
                        help='Specify the maximal amount of processes')

    parser.add_argument('-t', '--tlds-file', type=str, required=True,
                        help='Set the path to the tlds file')

    parser.add_argument('-p', '--c-profiling', action='store_true',
                        help='if set the cProfile will profile the script for one process')

    parser.add_argument('-d', '--destination', type=str,
                         help='Set the desination directory (must not exist)')

    parser.add_argument('-i', '--isp-ip-filter', action='store_true',
                        help='set if you want to filter isp ip domain names')

    parser.add_argument('-v', '--ip-version', type=str,
                        choices=[util.IPV4_IDENTIFIER, util.IPV6_IDENTIFIER],
                        help='specify the ipVersion')

    parser.add_argument('-f', '--white-list-file-path', type=str,
                        help='path to a file with a white list of IPs')

    parser.add_argument('-l', '--logging-file', type=str, default='preprocess.log',
                        help='Specify a logging file where the log should be saved')

    parser.add_argument('-c', '--config-file', type=str, dest='config_filepath',
                        is_config_file=True, help='The path to a config file')


def main():
    """Main function"""
    parser = configargparse.ArgParser(default_config_files=['ipdns_default.ini'])

    __create_parser_arguments(parser)
    args = parser.parse_args()

    start = time.time()

    global logger
    logger = util.setup_logger(args.logging_file, 'process')

    ipregex_text = select_ip_regex(args.regexStrategy)

    if args.isp_ip_filter:
        logger.info('using strategy: {}'.format(args.regexStrategy))
    else:
        logger.info('processing without ip filtering')

    ipregex = re.compile(ipregex_text, flags=re.MULTILINE)

    tlds = set()
    with open(args.tlds_file) as tldFile:
        for line in tldFile:
            line = line.strip()
            if line[0] != '#':
                tlds.add(line.lower())

    if not args.amount_processes:
        logger.critical('Amount of processes not defined or 0! Aborting')
        return 1
    if not args.destination:
        logger.critical('Destination path not defined! Aborting')
        return 1
    if not args.ip_version:
        logger.critical('IP version not defined! Aborting')
        return 1
    whitelist_trie = None
    whitelist = []
    if args.white_list_file_path:
        with open(args.white_list_file_path) as filter_list_file:
            for line in filter_list_file:
                whitelist.append(line.strip())

        whitelist_trie = marisa_trie.Trie(whitelist)

    # TODO: throw error when directory exists
    os.mkdir(args.destination)

    processes = []
    parsed_ips = set()
    parsed_ips_lock = mp.Lock()

    for i in range(0, args.amount_processes):
        if i == (args.amount_processes - 1):
            processes.append(mp.Process(target=preprocess_file_part_profile,
                                        args=(args, i, tlds, ipregex, whitelist_trie, parsed_ips,
                                              parsed_ips_lock, args.cProfiling),
                                        name='preprocessing_{}'.format(i)))
        else:
            processes.append(mp.Process(target=preprocess_file_part_profile,
                                        args=(args, i, tlds, ipregex, whitelist_trie, parsed_ips,
                                              parsed_ips_lock, False),
                                        name='preprocessing_{}'.format(i)))
        processes[i].start()

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


def select_ip_regex(regex_strategy):
    """Selects the regular expression according to the option set in the arguments"""
    if regex_strategy == 'abstract':
        # most abstract regex
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),' \
               r'.*(\1.*\2.*\3.*\4|\4.*\3.*\2.*\1).*$'
    elif regex_strategy == 'moderate':
        # slightly stricter regex
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),' \
               r'.*(\1.+\2.+\3.+\4|\4.+\3.+\2.+\1).*$'
    elif regex_strategy == 'strict':
        # regex with delimiters restricted to '.','-' and '_'
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),' \
               r'.*(0{0,2}?\1[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\3[\.\-_]' \
               r'0{0,2}?\4|0{0,2}?\4[\.\-_]0{0,2}?\3[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\1).*$'


def preprocess_file_part_profile(args, pnr: int, ipregex: re, tlds: {str},
                                 whitelist_trie: marisa_trie.Trie, parsed_ips: set(str),
                                 parsed_ips_lock: mp.Lock, profile: bool):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    if profile is set CProfile will profile the sanitizing
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """
    start_time = time.monotonic()
    if profile:
        profiler = cProfile.Profile()
        profiler.runctx('preprocess_file_part(args, pnr, ipregex, tlds, whitelist_trie, '
                        'parsed_ips, parsed_ips_lock)', globals(), locals())
        profiler.dump_stats('preprocess.profile')
    else:
        preprocess_file_part(args, pnr, ipregex, tlds, whitelist_trie, parsed_ips,
                             parsed_ips_lock)

    end_time = time.monotonic()
    logger.info('preprocess_file_part running time: {} profiled: {}'
                .format((end_time - start_time), profile))


BLOCK_SIZE = 10


def preprocess_file_part(args, pnr: int, ipregex: re, tlds: {str},
                         whitelist_trie: marisa_trie.Trie, parsed_ips: set(str),
                         parsed_ips_lock: mp.Lock):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """
    logger.info('starting')
    filename = util.get_path_filename(args.filename)
    label_stats = collections.defaultdict(int)
    is_ipv6 = args.ip_version == 'ipv6'

    with open(os.path.join(args.destination, '{0}-{1}.cor'.format(filename, pnr)), 'w',
              encoding='utf-8') as correct_file, \
            open(os.path.join(args.destination,
                              '{0}-{1}.ipencoded'.format(filename, pnr)),
                 'w', encoding='utf-8') as ip_encoded_file, \
            open(os.path.join(args.destination, '{0}-{1}.bad'.format(filename, pnr)), 'w',
                 encoding='utf-8') as bad_file, \
            open(os.path.join(args.destination, '{0}-{1}-dns.bad'.format(filename, pnr)), 'w',
                 encoding='utf-8') as bad_dns_file,  \
            open(os.path.join(args.destination, '{0}-{1}-custom-filterd'.format(filename, pnr)),
                 'w', encoding='utf-8') as custom_filter_file, \
            open(args.filename, encoding='ISO-8859-1') as rdns_file_handle:

        def is_standart_isp_domain(domain_line):
            """Basic check if the domain is a isp client domain address"""
            return ipregex.search(domain_line)

        def add_bad_line(domain_line):
            nonlocal bad_lines
            bad_lines.append(domain_line)
            if len(bad_lines) > 10 ** 3:
                write_bad_lines(util.ACCEPTED_CHARACTER)
                del bad_lines[:]

        def line_blocks():
            lines = []
            seek_before = 0
            seek_after = 0

            def prepare():
                nonlocal seek_before
                nonlocal seek_after
                nonlocal lines
                seek_before = BLOCK_SIZE*pnr
                seek_after = BLOCK_SIZE*args.amount_processes-BLOCK_SIZE*(pnr+1)
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

        def add_labels(new_rdns_record):
            for label_index, label in enumerate(new_rdns_record.domain_labels):
                # skip if tld
                if label_index == 0:
                    continue
                label_stats[label.label] += 1

        def write_bad_lines(good_characters):
            """
            write lines to the bad_file
            goodCharacters are all allowed Character
            """
            nonlocal bad_lines
            for bad_line in bad_lines:
                for character in set(bad_line).difference(good_characters):
                    bad_characters[character] += 1
                bad_file.write('{0}\n'.format(bad_line))

        def append_isp_ip_record(isp_line: util.Domain):
            nonlocal isp_ip_lines, count_isp_lines
            isp_ip_lines.append(isp_line)
            count_isp_lines += 1

            if len(isp_ip_lines) >= 10 ** 3:
                util.json_dump(isp_ip_lines, ip_encoded_file)
                ip_encoded_file.write('\n')
                del isp_ip_lines[:]

        def append_custom_filter_line(custom_filter_line: str):
            nonlocal custom_filter_lines
            custom_filter_lines.append(custom_filter_line)

            if len(custom_filter_lines) >= 10 ** 3:
                custom_filter_file.write('\n'.join(custom_filter_lines))
                custom_filter_file.write('\n')
                del custom_filter_lines[:]

        def append_good_record(record: util.Domain):
            nonlocal good_records
            good_records.append(record)
            add_labels(record)

            with parsed_ips_lock:
                parsed_ips.add(record.ip_for_version(args.ip_version))

            if len(good_records) >= 10 ** 3:
                util.json_dump(good_records, correct_file)
                correct_file.write('\n')
                del good_records[:]

        def append_bad_dns_record(record: util.Domain):
            nonlocal bad_dns_records
            bad_dns_records.append(record)

            if len(bad_dns_records) >= 10 ** 3:
                util.json_dump(bad_dns_records, bad_dns_file)
                bad_dns_file.write('\n')
                del bad_dns_records[:]

        bad_characters = collections.defaultdict(int)
        bad_lines = []
        count_good_lines = 0
        count_isp_lines = 0
        good_records = []
        bad_dns_records = []
        isp_ip_lines = []
        custom_filter_lines = []

        file_line_blocks = line_blocks()
        for line_block in file_line_blocks:
            for line in line_block:
                if len(line) == 0:
                    continue
                line = line.strip()
                ip_address, domain = line.split(',', 1)
                if set(domain).difference(util.ACCEPTED_CHARACTER):
                    add_bad_line(line)
                if whitelist_trie and ip_address not in whitelist_trie:
                    append_custom_filter_line(line)
                else:
                    if is_ipv6:
                        rdns_record = Domain(domain, ipv6_address=ip_address)
                    else:
                        rdns_record = Domain(domain, ip_address=ip_address)
                    # is not None is correct because it could also be an empty list and that is
                    # allowed
                    if args.white_list is not None and ip_address not in args.white_list:
                        append_custom_filter_line(line)
                    elif not is_ipv6 and args.isp_ip_filter and is_standart_isp_domain(line):
                        append_isp_ip_record(rdns_record)
                    elif not is_ipv6 and args.isp_ip_filter and \
                            util.is_ip_hex_encoded_simple(ip_address, domain):
                        append_isp_ip_record(rdns_record)
                    elif args.isp_ip_filter and util.int_to_alphanumeric(
                            util.ip_to_int(ip_address, args.ip_version)) in domain:
                        append_isp_ip_record(rdns_record)
                    else:
                        if rdns_record.domain_labels[0].label.lower() in tlds:
                            count_good_lines += 1
                            append_good_record(rdns_record)
                        else:
                            append_bad_dns_record(rdns_record)

        util.json_dump(good_records, correct_file)
        correct_file.write('\n')
        util.json_dump(bad_dns_records, bad_dns_file)
        bad_dns_file.write('\n')
        util.json_dump(isp_ip_lines, ip_encoded_file)
        ip_encoded_file.write('\n')

        write_bad_lines(util.ACCEPTED_CHARACTER)

        logger.info('good lines: {} ips lines: {}'.format(count_good_lines, count_isp_lines))
        with open(os.path.join(args.destination, '{0}-{1}-character.stats'.format(filename, pnr)),
                  'w', encoding='utf-8') as characterStatsFile:
            json.dump(bad_characters, characterStatsFile)

        with open(os.path.join(args.destination,
                               '{0}-{1}-domain-label.stats'.format(filename, pnr)),
                  'w', encoding='utf-8') as labelStatFile:
            json.dump(label_stats, labelStatFile)


if __name__ == '__main__':
    main()
