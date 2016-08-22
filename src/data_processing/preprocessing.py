#!/usr/bin/env python3
"""
sanitizing and classification of the domain names
saves results in the folder ./rdns_results

40975774 + 46280879 + 53388841 + 57895044 + 67621408 + 76631142 + 88503028 + 67609127
= 498.905.243 ohne fuehrende 0en

Further filtering ideas: www pages and pages with only 2 levels
"""
import argparse
import re
import cProfile
import time
import os
import collections
import multiprocessing as mp
import ujson as json
import mmap
import configparser
import sys

from . import util
from .util import Domain

logger = None


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('filename', help='filename to sanitize', type=str)
    parser.add_argument('-n', '--num-processes', type=int, dest='numProcesses',
                        help='Specify the maximal amount of processes')
    parser.add_argument('-t', '--tlds-file', type=str, required=True,
                        dest='tlds_file', help='Set the path to the tlds file')
    parser.add_argument('-s', '--strategy', type=str, dest='regexStrategy',
                        choices=['strict', 'abstract', 'moderate'],
                        default='abstract', help='Specify a regex Strategy')
    parser.add_argument('-p', '--profile', action='store_true', dest='cProfiling',
                        help='if set the cProfile will profile the script for one process')
    parser.add_argument('-d', '--destination', type=str, dest='destination',
                        help='Set the desination directory (must exist)')
    parser.add_argument('-i', '--isp-ip-filter', action='store_true', dest='isp_ip_filter',
                        help='set if you want to filter isp ip domain names')
    parser.add_argument('-v', '--ip-version', type=str, dest='ip_version',
                        choices=[util.IPV4_IDENTIFIER, util.IPV6_IDENTIFIER],
                        help='specify the ipVersion')
    parser.add_argument('-f', '--white-list-file', type=str, dest='white_list_file_path',
                        help='path to a file with a white list of IPs')
    parser.add_argument('-l', '--logging-file', type=str, default='preprocess.log', dest='log_file',
                        help='Specify a logging file where the log should be saved')
    parser.add_argument('-c', '--config-file', type=str, dest='config_filepath',
                        help='The path to a config file')


class Config(object):
    """The Config object"""
    filename = None
    amount_processes = None
    destination = None
    isp_ip_filter = False
    ip_version = None
    white_list = None


class ConfigPropertyKey(object):
    """Propertykeys"""
    default_section_key = 'DEFAULT'
    amount_processes_key = 'amount processes'
    destination_key = 'destination'
    isp_ip_filter_key = 'isp ip filter'
    ip_version_key = 'ip version'
    white_list_key = 'white list file'


def create_default_config(config_parser: configparser.ConfigParser):
    """Adds all default values to the config_parser"""
    config_parser[ConfigPropertyKey.default_section_key] = {}
    default_section = config_parser[ConfigPropertyKey.default_section_key]
    default_section[ConfigPropertyKey.amount_processes_key] = str(8)
    default_section[ConfigPropertyKey.destination_key] = 'rdns-results'
    default_section[ConfigPropertyKey.isp_ip_filter_key] = str(False)
    default_section[ConfigPropertyKey.ip_version_key] = 'ipv4'


def main():
    """Main function"""
    start = time.time()
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    global logger
    logger = util.setup_logger(args.log_file, 'process')

    config = Config()
    if args.config_filepath:
        config_parser = configparser.ConfigParser()
        if os.path.isfile(args.config_filepath):
            config_parser.read(args.config_filepath)
            if ConfigPropertyKey.default_section_key not in config_parser:
                print('{} section missing in config file! Tip: if you specify a non existent file '
                      'in config a default one will be created')
            else:
                default_section = config_parser[ConfigPropertyKey.default_section_key]
                if ConfigPropertyKey.amount_processes_key in default_section and \
                        default_section.get(ConfigPropertyKey.amount_processes_key):
                    config.amount_processes = int(default_section.get(
                        ConfigPropertyKey.amount_processes_key))
                else:
                    print('{} key is required to have a value (Default: 8)'.format(
                        ConfigPropertyKey.amount_processes_key), file=sys.stderr)
                    return
                if ConfigPropertyKey.destination_key in default_section and \
                        default_section.get(ConfigPropertyKey.destination_key):
                    config.destination = default_section.get(ConfigPropertyKey.destination_key)
                else:
                    print('{} key is required to have a value (Default: rdns-results)'.format(
                        ConfigPropertyKey.destination_key), file=sys.stderr)
                    return
                if ConfigPropertyKey.isp_ip_filter_key in default_section:
                    config.isp_ip_filter = default_section.getboolean(
                        ConfigPropertyKey.isp_ip_filter_key)
                else:
                    print('{} key is required to have a value (Default: False)'.format(
                        ConfigPropertyKey.isp_ip_filter_key), file=sys.stderr)
                    return
                if ConfigPropertyKey.ip_version_key in default_section and \
                        default_section.get(ConfigPropertyKey.ip_version_key) in ['ipv4', 'ipv6']:
                    config.ip_version = default_section.get('ip version')
                else:
                    print('{} key is required to have a value (choices: ipv4, ipv6)(Default: ipv4)'
                          .format(ConfigPropertyKey.destination_key), file=sys.stderr)
                    return
                if ConfigPropertyKey.white_list_key in default_section:
                    if os.path.isfile(default_section.get(ConfigPropertyKey.white_list_key)):
                        with open(default_section.get(ConfigPropertyKey.white_list_key)) as f_file:
                            config.white_list = []
                            for line in f_file:
                                config.white_list.append(line.strip())
                    else:
                        print('{} key has to be a valid file if specified!'
                              .format(ConfigPropertyKey.white_list_key), file=sys.stderr)
                        return
        else:
            logger.info('Creating new default config file')
            create_default_config(config_parser)
            with open(args.config_filepath, 'w') as config_file:
                config_parser.write(config_file)

    ipregex_text = select_ip_regex(args.regexStrategy)
    if not args.isp_ip_filter:
        logger.info('processing without ip filtering')

    if args.isp_ip_filter:
        logger.info('using strategy: {}'.format(args.regexStrategy))
    else:
        logger.info('not filtering ip domain names')
    ipregex = re.compile(ipregex_text, flags=re.MULTILINE)

    tlds = set()
    with open(args.tlds_file) as tldFile:
        for line in tldFile:
            line = line.strip()
            if line[0] != '#':
                tlds.add(line.lower())

    config.filename = args.filename
    if args.numProcesses:
        config.amount_processes = args.numProcesses
    if args.destination:
        config.destination = args.destination
    if args.isp_ip_filter:
        config.isp_ip_filter = args.isp_ip_filter
    if args.ip_version:
        config.ip_version = args.ip_version
    if args.white_list_file_path:
        del config.white_list
        config.white_list = []
        with open(args.white_list_file_path) as filter_list_file:
            for line in filter_list_file:
                config.white_list.append(line.strip())

    os.mkdir(config.destination)

    processes = [None] * config.amount_processes

    for i in range(0, len(processes)):
        if i == (config.amount_processes - 1):
            processes[i] = mp.Process(target=preprocess_file_part_profile,
                                      args=(config, i, ipregex, tlds, args.cProfiling),
                                      name='preprocessing_{}'.format(i))
        else:
            processes[i] = mp.Process(target=preprocess_file_part_profile,
                                      args=(config, i, ipregex, tlds, False),
                                      name='preprocessing_{}'.format(i))
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


def preprocess_file_part_profile(config: Config, pnr: int, ipregex: re, tlds: {str}, profile: bool):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    if profile is set CProfile will profile the sanitizing
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """
    start_time = time.monotonic()
    if profile:
        profiler = cProfile.Profile()
        profiler.runctx('preprocess_file_part(config, pnr, ipregex, tlds)', globals(), locals())
        profiler.dump_stats('preprocess.profile')
    else:
        preprocess_file_part(config, pnr, ipregex, tlds)

    end_time = time.monotonic()
    logger.info('preprocess_file_part running time: {} profiled: {}'
                .format((end_time - start_time), profile))


BLOCK_SIZE = 10


def preprocess_file_part(config: Config, pnr: int, ipregex: re, tlds: {str}):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """
    logger.info('starting')
    filename = util.get_path_filename(config.filename)
    label_stats = collections.defaultdict(int)
    is_ipv6 = config.ip_version == 'ipv6'

    with open(os.path.join(config.destination, '{0}-{1}.cor'.format(filename, pnr)), 'w',
              encoding='utf-8') as correct_file, \
            open(os.path.join(config.destination,
                              '{0}-{1}-ip-encoded.domain'.format(filename, pnr)),
                 'w', encoding='utf-8') as ip_encoded_file, \
            open(os.path.join(config.destination, '{0}-{1}-hex-ip.domain'.format(filename, pnr)),
                 'w', encoding='utf-8') as hex_ip_encoded_file, \
            open(os.path.join(config.destination, '{0}-{1}.bad'.format(filename, pnr)), 'w',
                 encoding='utf-8') as bad_file, \
            open(os.path.join(config.destination, '{0}-{1}-dns.bad'.format(filename, pnr)), 'w',
                 encoding='utf-8') as bad_dns_file,  \
            open(os.path.join(config.destination, '{0}-{1}-custom-filterd'.format(filename, pnr)),
                 'w', encoding='utf-8') as custom_filter_file, \
            open(config.filename, encoding='ISO-8859-1') as rdns_file_handle, \
            mmap.mmap(rdns_file_handle.fileno(), 0, access=mmap.ACCESS_READ) as rdns_file_mmap:

        def is_standart_isp_domain(domain_line):
            """Basic check if the domain is a isp client domain address"""
            return ipregex.search(domain_line)

        def add_bad_line(domain_line):
            nonlocal bad_lines
            bad_lines.append(domain_line)
            if len(bad_lines) > 10 ** 3:
                write_bad_lines(util.ACCEPTED_CHARACTER)
                del bad_lines[:]

        def line_blocks_mmap():
            def seek_mmap(amount):
                for _ in range(0, amount):
                    rdns_file_mmap.readline()

            while True:
                lines = []
                seek_mmap(BLOCK_SIZE*pnr)
                for _ in range(0, BLOCK_SIZE):
                    seek_line = rdns_file_mmap.readline().decode('ISO-8859-1')
                    if seek_line:
                        lines.append(seek_line)
                if not lines:
                    break
                seek_mmap(BLOCK_SIZE*config.amount_processes-BLOCK_SIZE*(pnr+1))
                yield lines

        def line_blocks():
            lines = []
            seek_before = 0
            seek_after = 0

            def prepare():
                nonlocal seek_before
                nonlocal seek_after
                nonlocal lines
                seek_before = BLOCK_SIZE*pnr
                seek_after = BLOCK_SIZE*config.amount_processes-BLOCK_SIZE*(pnr+1)
                del lines[:]

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

        def append_isp_ip_line(isp_line: str):
            nonlocal isp_ip_lines
            isp_ip_lines.append(isp_line)
            if len(isp_ip_lines) >= 10 ** 3:
                ip_encoded_file.write('\n'.join(isp_ip_lines))
                ip_encoded_file.write('\n')
                del isp_ip_lines[:]

        def append_hex_ip_line(hex_line: str):
            nonlocal hex_ip_lines
            hex_ip_lines.append(hex_line)
            if len(hex_ip_lines) >= 10 ** 3:
                hex_ip_encoded_file.write('\n'.join(hex_ip_lines))
                hex_ip_encoded_file.write('\n')
                del hex_ip_lines[:]

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
        good_records = []
        bad_dns_records = []
        hex_ip_lines = []
        isp_ip_lines = []
        custom_filter_lines = []

        file_line_blocks = line_blocks()
        for line_block in file_line_blocks:
            for line in line_block:
                if len(line) == 0:
                    continue
                line = line.strip()
                index = line.find(',')
                if set(line[(index + 1):]).difference(util.ACCEPTED_CHARACTER):
                    add_bad_line(line)
                else:
                    ip_address, domain = line.split(',', 1)
                    # is not None is correct because it could also be an empty list and that is
                    # allowed
                    filter_ips = not is_ipv6 and config.isp_ip_filter
                    if config.white_list is not None and ip_address not in config.white_list:
                        append_custom_filter_line(line)
                    elif filter_ips and is_standart_isp_domain(line):
                        append_isp_ip_line(line)
                    elif filter_ips and util.is_ip_hex_encoded_simple(ip_address, domain):
                        append_hex_ip_line(line)
                    else:
                        if is_ipv6:
                            rdns_record = Domain(domain, ipv6_address=ip_address)
                        else:
                            rdns_record = Domain(domain, ip_address=ip_address)
                        if rdns_record.domain_labels[0].label.lower() in tlds:
                            count_good_lines += 1
                            append_good_record(rdns_record)
                        else:
                            append_bad_dns_record(rdns_record)

        util.json_dump(good_records, correct_file)
        util.json_dump(bad_dns_records, bad_dns_file)
        util.json_dump(hex_ip_lines, hex_ip_encoded_file)

        write_bad_lines(util.ACCEPTED_CHARACTER)

        logger.info('good lines: {}'.format(count_good_lines))
        with open(os.path.join(config.destination, '{0}-{1}-character.stats'.format(filename, pnr)),
                  'w', encoding='utf-8') as characterStatsFile:
            json.dump(bad_characters, characterStatsFile)

        with open(os.path.join(config.destination,
                               '{0}-{1}-domain-label.stats'.format(filename, pnr)),
                  'w', encoding='utf-8') as labelStatFile:
            json.dump(label_stats, labelStatFile)

        # for character, count in bad_characters.items():
        #     print('pnr {0}: Character {1} (unicode: {2}) has {3} occurences'.format(pnr, \
        #         character, ord(character), count))


if __name__ == '__main__':
    main()
