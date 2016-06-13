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
from multiprocessing import Process
import ujson as json
import logging

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
    parser.add_argument('-l', '--logging-file', type=str, default='find_drop.log', dest='log_file',
                        help='Specify a logging file where the log should be saved')


def main():
    """Main function"""
    start = time.time()
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    logging.basicConfig(filename=args.log_file, level=logging.DEBUG,
                        format='[%(levelname)s][%(asctime)s]:[%(processName)s] '
                               '%(filename)s:%(lineno)d %(message)s', datefmt='%s/%m/%Y %H:%M:%S')

    os.mkdir(args.destination)

    ipregexText = select_ip_regex(args.regexStrategy)
    if not args.ip_filter:
        ipregexText = r''

    if args.ip_filter:
        logging.info('using strategy: {}'.format(args.regexStrategy))
    else:
        logging.info('not filtering ip domain names')
    ipregex = re.compile(ipregexText, flags=re.MULTILINE)

    lineCount = util.count_lines(args.filename)

    tlds = set()
    with open(args.tlds_file) as tldFile:
        for line in tldFile:
            line = line.strip()
            if line[0] != '#':
                tlds.add(line.lower())

    processes = [None] * args.numProcesses

    for i in range(0, len(processes)):
        if i == (args.numProcesses - 1):
            processes[i] = Process(target=preprocess_file_part_profile,
                                   args=(args.filename, i, (i * (lineCount // args.numProcesses),
                                         lineCount), ipregex, tlds, args.destination,
                                         args.cProfiling), name='preprocessing_{}'.format(i))
        else:
            processes[i] = Process(target=preprocess_file_part_profile,
                                   args=(args.filename, i, (i * (lineCount // args.numProcesses),
                                         (i + 1) * (lineCount // args.numProcesses)),
                                         ipregex, tlds, args.destination, False),
                                   name='preprocessing_{}'.format(i))
        processes[i].start()

    for process in processes:
        process.join()

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


def preprocess_file_part_profile(filename, pnr, sector, ipregex, tlds, destination_dir, profile):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    if profile is set CProfile will profile the sanitizing
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """
    startTime = time.monotonic()
    # TODO cprofile with output to file
    if profile:
        cProfile.runctx('preprocess_file_part(filename, pnr, sector,'
                        ' ipregex, tlds, destination_dir)',  globals(), locals())
    else:
        preprocess_file_part(filename, pnr, sector, ipregex, tlds, destination_dir)

    endTime = time.monotonic()
    logging.info('pnr {0}: preprocess_file_part running time: {1} profiled: {2}'
          .format(pnr, (endTime - startTime), profile))


def preprocess_file_part(filepath, pnr, sector, ipregex, tlds, destination_dir):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """

    start, end = sector
    logging.info('pnr', pnr, 'start', start, 'end', end)
    filename = util.get_path_filename(filepath)
    filepart = open(filepath, encoding='ISO-8859-1')
    labelDict = collections.defaultdict(int)

    util.seek_lines(filepart, start)

    # TODO use os path join
    with open(destination_dir + '/{0}-{1}.cor'.format(filename, pnr), 'w',
              encoding='utf-8') as correctFile, open(
                destination_dir + '/{0}-{1}-ip-encoded.domain'.format(filename, pnr), 'w',
                encoding='utf-8') as ipEncodedFile, open(
                destination_dir + '/{0}-{1}-hex-ip.domain'.format(filename, pnr), 'w',
                encoding='utf-8') as hexIpEncodedFile, open(
                destination_dir + '/{0}-{1}.bad'.format(filename, pnr), 'w',
                encoding='utf-8') as badFile, open(
                destination_dir + '/{0}-{1}-dns.bad'.format(filename, pnr), 'w',
                encoding='utf-8') as badDnsFile:
        def is_standart_isp_domain(domain_line):
            """Basic check if the domain is a isp client domain address"""
            return ipregex.search(domain_line)

        def has_bad_characters_for_regex(dnsregex, domain_line):
            """
            Execute regex on line
            return true if regex had a match
            """
            return dnsregex.search(domain_line) is None

        def add_bad_line(domain_line):
            nonlocal badLines
            badLines.append(domain_line)
            if len(badLines) > 10 ** 3:
                write_bad_lines(badFile, badLines, util.ACCEPTED_CHARACTER)
                badLines = []

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
            returns all bad Character found in the lines in a list
            """
            for line in lines:
                for character in set(line):
                    if character not in goodCharacters:
                        badCharacterDict[character] += 1
                badFile.write('{0}\n'.format(line))

        def append_hex_ip_line(app_line):
            nonlocal hexIpRecords
            hexIpRecords.append(app_line)
            if len(hexIpRecords) >= 10 ** 5:
                hexIpEncodedFile.write('\n'.join(hexIpRecords))
                hexIpRecords = []

        def append_good_record(record):
            nonlocal goodRecords, countGoodLines
            goodRecords.append(record)
            countGoodLines += 1
            add_labels(record)
            if len(goodRecords) >= 10 ** 5:
                util.json_dump(goodRecords, correctFile)
                correctFile.write('\n')
                goodRecords = []

        def append_bad_dns_record(record):
            nonlocal badDnsRecords
            badDnsRecords.append(record)
            if len(badDnsRecords) >= 10 ** 5:
                util.json_dump(badDnsRecords, badDnsFile)
                badDnsFile.write('\n')
                badDnsRecords = []

        badCharacterDict = collections.defaultdict(int)
        badLines = []
        countGoodLines = 0
        goodRecords = []
        badDnsRecords = []
        hexIpRecords = []

        lineCount = start
        for line in filepart:
            if len(line) == 0:
                continue
            line = line.strip()
            index = line.find(',')
            if has_bad_characters_for_regex(util.DNS_REGEX, line[(index + 1):]):
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
                            append_good_record(rdnsRecord)

                    else:
                        append_bad_dns_record(rdnsRecord)

            lineCount += 1
            if lineCount == end:
                break

        util.json_dump(goodRecords, correctFile)
        util.json_dump(badDnsRecords, badDnsFile)
        util.json_dump(hexIpRecords, hexIpEncodedFile)

        write_bad_lines(badFile, badLines, util.ACCEPTED_CHARACTER)

        logging.info('pnr {0}: good lines: {1}'.format(pnr, countGoodLines))
        with open(destination_dir + '/{0}-{1}-character.stats'.format(filename, pnr),
                  'w', encoding='utf-8') as characterStatsFile:
            json.dump(badCharacterDict, characterStatsFile)
        # with open(destination_dir + '/{0}-{1}-character.stats'.format(filename, pnr),
        #           'wb') as characterStatsFile:
        #     pickle.dump(badCharacterDict, characterStatsFile)

        with open(destination_dir + '/{0}-{1}-domain-label.stats'.format(filename, pnr),
                  'w', encoding='utf-8') as labelStatFile:
            json.dump(labelDict, labelStatFile)
        # with open(destination_dir + '/{0}-{1}-domain-label.stats'.format(filename, pnr),
        #           'wb') as labelStatFile:
        #     pickle.dump(labelDict, labelStatFile)

        # for character, count in badCharacterDict.items():
        #     print('pnr {0}: Character {1} (unicode: {2}) has {3} occurences'.format(pnr, \
        #         character, ord(character), count))


if __name__ == '__main__':
    main()
