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
import logging
import mmap

from . import util
from .util import Domain


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('filename', help='filename to sanitize', type=str)
    parser.add_argument('-n', '--num-processes', default=16, type=int,
                        dest='numProcesses',
                        help='Specify the maximal amount of processes')
    parser.add_argument('-t', '--tlds-file', type=str, required=True,
                        dest='tlds_file', help='Set the path to the tlds file')
    parser.add_argument('-s', '--strategy', type=str, dest='regexStrategy',
                        choices=['strict', 'abstract', 'moderate'],
                        default='abstract',
                        help='Specify a regex Strategy')
    parser.add_argument('-p', '--profile', action='store_true', dest='cProfiling',
                        help='if set the cProfile will profile the script for one process')
    parser.add_argument('-d', '--destination', type=str, default='rdns_results',
                        dest='destination', help='Set the desination directory (must exist)')
    parser.add_argument('-i', '--ip-filter', action='store_true', dest='ip_filter',
                        help='set if you want to filter isp ip domain names')
    parser.add_argument('-l', '--logging-file', type=str, default='preprocess.log', dest='log_file',
                        help='Specify a logging file where the log should be saved')


def main():
    """Main function"""
    start = time.time()
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    util.setup_logging(args.log_file)

    os.mkdir(args.destination)

    ipregexText = select_ip_regex(args.regexStrategy)
    if not args.ip_filter:
        ipregexText = r'$^'

    if args.ip_filter:
        logging.info('using strategy: {}'.format(args.regexStrategy))
    else:
        logging.info('not filtering ip domain names')
    ipregex = re.compile(ipregexText, flags=re.MULTILINE)

    tlds = set()
    with open(args.tlds_file) as tldFile:
        for line in tldFile:
            line = line.strip()
            if line[0] != '#':
                tlds.add(line.lower())

    processes = [None] * args.numProcesses

    for i in range(0, len(processes)):
        if i == (args.numProcesses - 1):
            processes[i] = mp.Process(target=preprocess_file_part_profile,
                                      args=(args.filename, i, args.numProcesses, ipregex,
                                            tlds, args.destination, args.cProfiling),
                                      name='preprocessing_{}'.format(i))
        else:
            processes[i] = mp.Process(target=preprocess_file_part_profile,
                                      args=(args.filename, i, args.numProcesses, ipregex,
                                            tlds, args.destination, False),
                                      name='preprocessing_{}'.format(i))
        processes[i].start()

    alive = len(processes)
    while alive > 0:
        try:
            for process in processes:
                process.join()
            process_sts = [pro.is_alive() for pro in processes]
            if process_sts.count(True) != alive:
                logging.info('{} processes alive'.format(process_sts.count(True)))
                alive = process_sts.count(True)
        except KeyboardInterrupt:
            pass

    end = time.time()
    logging.info('Running time: {0}'.format((end - start)))


def select_ip_regex(regexStrategy):
    """Selects the regular expression according to the option set in the arguments"""
    if regexStrategy == 'abstract':
        # most abstract regex
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),' \
               r'.*(\1.*\2.*\3.*\4|\4.*\3.*\2.*\1).*$'
    elif regexStrategy == 'moderate':
        # slightly stricter regex
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),' \
               r'.*(\1.+\2.+\3.+\4|\4.+\3.+\2.+\1).*$'
    elif regexStrategy == 'strict':
        # regex with delimiters restricted to '.','-' and '_'
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),' \
               r'.*(0{0,2}?\1[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\3[\.\-_]' \
               r'0{0,2}?\4|0{0,2}?\4[\.\-_]0{0,2}?\3[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\1).*$'


def preprocess_file_part_profile(filepath: str, pnr: int, amount_processes: int, ipregex: re,
                                 tlds: {str},  destination_dir: str, profile):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    if profile is set CProfile will profile the sanitizing
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """
    startTime = time.monotonic()
    if profile:
        profiler = cProfile.Profile()
        profiler.runctx('preprocess_file_part(filepath, pnr, amount_processes, ipregex'
                        ', tlds, destination_dir)', globals(), locals())
        profiler.dump_stats('preprocess.profile')
    else:
        preprocess_file_part(filepath, pnr, amount_processes, ipregex, tlds, destination_dir)

    endTime = time.monotonic()
    logging.info('pnr {0}: preprocess_file_part running time: {1} profiled: {2}'
                 .format(pnr, (endTime - startTime), profile))


def preprocess_file_part(filepath: str, pnr: int, amount_processes: int, ipregex: re,
                         tlds: {str}, destination_dir: str):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """
    logging.info('starting')
    rdns_file_handle = open(filepath, encoding='ISO-8859-1')
    rdns_file = mmap.mmap(rdns_file_handle.fileno(), 0, access=mmap.ACCESS_READ)
    filename = util.get_path_filename(filepath)
    labelDict = collections.defaultdict(int)

    with open(os.path.join(destination_dir, '{0}-{1}.cor'.format(filename, pnr)), 'w',
              encoding='utf-8') as correctFile, open(os.path.join(
            destination_dir, '{0}-{1}-ip-encoded.domain'.format(filename, pnr)), 'w',
            encoding='utf-8') as ipEncodedFile, open(os.path.join(
            destination_dir, '{0}-{1}-hex-ip.domain'.format(filename, pnr)), 'w',
            encoding='utf-8') as hexIpEncodedFile, open(os.path.join(
            destination_dir, '{0}-{1}.bad'.format(filename, pnr)), 'w',
            encoding='utf-8') as badFile, open(os.path.join(
            destination_dir, '{0}-{1}-dns.bad'.format(filename, pnr)), 'w',
            encoding='utf-8') as badDnsFile:

        def is_standart_isp_domain(domain_line):
            """Basic check if the domain is a isp client domain address"""
            return ipregex.search(domain_line)

        def add_bad_line(domain_line):
            nonlocal badLines
            badLines.append(domain_line)
            if len(badLines) > 10 ** 3:
                write_bad_lines(badFile, badLines, util.ACCEPTED_CHARACTER)
                del badLines[:]

        def line_blocks():
            def seek_mmap(amount):
                for _ in range(0, amount):
                    rdns_file.readline()

            while True:
                lines = []
                seek_mmap(10*pnr)
                for _ in range(0, 10):
                    line = rdns_file.readline().decode('ISO-8859-1')
                    if line:
                        lines.append(line)
                if not lines:
                    break
                seek_mmap(10*amount_processes-10*(pnr+1))
                yield lines

        def add_labels(new_rdns_record):
            for index, label in enumerate(new_rdns_record.domain_labels):
                # skip if tld
                if index == 0:
                    continue
                labelDict[label.label] += 1

        def write_bad_lines(badFile, lines, goodCharacters):
            """
            write lines to the badFile
            goodCharacters are all allowed Character
            """
            for line in lines:
                for character in set(line).difference(goodCharacters):
                    badCharacterDict[character] += 1
                badFile.write('{0}\n'.format(line))

        def append_hex_ip_line(app_line):
            nonlocal hexIpRecords
            hexIpRecords.append(app_line)
            if len(hexIpRecords) >= 10 ** 5:
                hexIpEncodedFile.write('\n'.join(hexIpRecords))
                del hexIpRecords[:]

        def append_good_record(record):
            nonlocal goodRecords
            goodRecords.append(record)
            add_labels(record)
            if len(goodRecords) >= 10 ** 5:
                util.json_dump(goodRecords, correctFile)
                correctFile.write('\n')
                del goodRecords[:]

        def append_bad_dns_record(record):
            nonlocal badDnsRecords
            badDnsRecords.append(record)
            if len(badDnsRecords) >= 10 ** 5:
                util.json_dump(badDnsRecords, badDnsFile)
                badDnsFile.write('\n')
                del badDnsRecords[:]

        badCharacterDict = collections.defaultdict(int)
        badLines = []
        countGoodLines = 0
        goodRecords = []
        badDnsRecords = []
        hexIpRecords = []

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
                    ipAddress, domain = line.split(',', 1)
                    if is_standart_isp_domain(line):
                        ipEncodedFile.write('{0}\n'.format(line))
                    else:
                        rdnsRecord = Domain(domain, ip_address=ipAddress)
                        if rdnsRecord.domain_labels[0].label.lower() in tlds:
                            if util.is_ip_hex_encoded_simple(ipAddress, domain):
                                append_hex_ip_line(line)
                            else:
                                countGoodLines += 1
                                append_good_record(rdnsRecord)

                        else:
                            append_bad_dns_record(rdnsRecord)

        util.json_dump(goodRecords, correctFile)
        util.json_dump(badDnsRecords, badDnsFile)
        util.json_dump(hexIpRecords, hexIpEncodedFile)

        rdns_file.close()
        rdns_file_handle.close()

        write_bad_lines(badFile, badLines, util.ACCEPTED_CHARACTER)

        logging.info('good lines: {}'.format(countGoodLines))
        with open(os.path.join(destination_dir, '{0}-{1}-character.stats'.format(filename, pnr)),
                  'w', encoding='utf-8') as characterStatsFile:
            json.dump(badCharacterDict, characterStatsFile)

        with open(os.path.join(destination_dir, '{0}-{1}-domain-label.stats'.format(filename, pnr)),
                  'w', encoding='utf-8') as labelStatFile:
            json.dump(labelDict, labelStatFile)

        # for character, count in badCharacterDict.items():
        #     print('pnr {0}: Character {1} (unicode: {2}) has {3} occurences'.format(pnr, \
        #         character, ord(character), count))


if __name__ == '__main__':
    main()
