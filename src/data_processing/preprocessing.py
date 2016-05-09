#!/usr/bin/env python3
"""
sanitizing and classification of the domain names
saves results in the folder ./rdns_results

40975774 + 46280879 + 53388841 + 57895044 + 67621408 + 76631142 + 88503028 + 67609127
= 498.905.243 ohne fuehrende 0en

Further filtering ideas: www pages and pages with only 2 levels
"""
from __future__ import print_function
import argparse
import re
import pickle
import cProfile
import time
import os
from multiprocessing import Process

from . import util
from .util import Domain


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('filename', help='filename to sanitize', type=str)
    parser.add_argument('-n', '--num-processes', default=16, type=int,
                        dest='numProcesses',
                        help='Specify the maximal amount of processes')
    parser.add_argument('-s', '--strategy', type=str, dest='regexStrategy',
                        choices=['strict', 'abstract', 'moderate'],
                        default='abstract',
                        help='Specify a regex Strategy')
    parser.add_argument('-p', '--profile', action='store_true',
                        dest='cProfiling',
                        help='if set the cProfile will profile the script for one process')


def main(args=None):
    """Main function"""
    start = time.time()
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    if not os.path.exists('rdns_results'):
        os.mkdir('rdns_results')

    ipregexText = select_ip_regex(args.regexStrategy)

    print('using strategy: {}'.format(args.regexStrategy))
    ipregex = re.compile(ipregexText, flags=re.MULTILINE)

    lineCount = util.count_lines(args.filename)

    tlds = set()
    with open('collectedData/tlds.txt') as tldFile:
        for line in tldFile:
            if line[0] != '#':
                tlds.add(line[:-1].lower())

    processes = [None] * args.numProcesses
    filename = util.get_path_filename(args.filename)

    for i, process in enumerate(processes):
        if i == (args.numProcesses - 1):
            process = Process(target=preprocess_file_part_profile,
                              args=(filename, i, i * (lineCount // args.numProcesses),
                                    lineCount, ipregex, tlds, args.cProfiling))
        else:
            process = Process(target=preprocess_file_part_profile,
                              args=(filename, i, i * (lineCount // args.numProcesses),
                                    (i + 1) * (lineCount // args.numProcesses),
                                    ipregex, tlds, False))
        process.start()

    for process in processes:
        process.join()

    end = time.time()
    print('Running time: {0}'.format((end - start)))


def select_ip_regex(regexStrategy):
    """Selects the regular expression according to the option set in the arguments"""
    if regexStrategy == 'abstract':
        # most abstract regex
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),'\
               r'.*(\1.*\2.*\3.*\4|\4.*\3.*\2.*\1).*$'
    elif regexStrategy == 'moderate':
        # slightly stricter regex
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),'\
               r'.*(\1.+\2.+\3.+\4|\4.+\3.+\2.+\1).*$'
    elif regexStrategy == 'strict':
        # regex with delimiters restricted to '.','-' and '_'
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),'\
               r'.*(0{0,2}?\1[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\3[\.\-_]'\
               r'0{0,2}?\4|0{0,2}?\4[\.\-_]0{0,2}?\3[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\1).*$'


def preprocess_file_part_profile(filename, pnr, start, end, ipregex, tlds, profile):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    if profile is set CProfile will profile the sanitizing
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """
    startTime = time.clock()
    if profile:
        cProfile.runctx('preprocess_file_part(filename, pnr, start, end, ipregex, tlds)',
                        globals(), locals())
    else:
        preprocess_file_part(filename, pnr, start, end, ipregex, tlds)

    endTime = time.clock()
    print('pnr {0}: preprocess_file_part running time: {1} profiled: {2}'
          .format(pnr, (endTime - startTime), profile))


def preprocess_file_part(filename, pnr, start, end, ipregex, tlds):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """

    def is_standart_isp_domain(line):
        """Basic check if the domain is a isp client domain address"""
        return ipregex.search(line)

    def has_bad_characters_for_regex(dnsregex, line):
        """
        Execute regex on line
        return true if regex had a match
        """
        return dnsregex.search(line) is None

    def split_line(line):
        """
        splits the line after the first ','
        returns both parts without ',' in a tuple
        """
        index = line.find(',')
        return (line[:index], line[(index + 1):])

    filepart = open(filename, 'r', encoding='ISO-8859-1')
    labelDict = {}

    def add_labels(rdnsRecord):
        for key, label in rdnsRecord['domainLabels'].items():
            if key == 'tld':
                continue
            if label in labelDict.keys():
                labelDict[label] = labelDict[label] + 1
            else:
                labelDict[label] = 1

    util.seek_lines(filepart, start)
    writeFiles = {
        'correct': open('rdns_results/{0}-{1}.cor'.format(filename, pnr), 'w', encoding='utf-8'),
        'ipEncoded': open('rdns_results/{0}-{1}-ip-encoded.domain'.format(filename, pnr),
                                'w', encoding='utf-8'),
        'hexIpEncoded': open('rdns_results/{0}-{1}-hex-ip.domain'.format(filename, pnr),
                       'w', encoding='utf-8'),
        'bad': open('rdns_results/{0}-{1}.bad'.format(filename, pnr), 'w', encoding='utf-8'),
        'badDNS': open('rdns_results/{0}-{1}-dns.bad'.format(filename, pnr), 'w', encoding='utf-8')
    }

    badCharacterDict = {}
    badLines = []
    countGoodLines = 0
    goodRecords = []
    badDnsRecords = []
    hexIpRecords = []

    def add_bad_line(line):
        nonlocal badLines
        badLines.append(line)
        if len(badLines) > 10 ** 3:
            write_bad_lines(writeFiles['bad'], badLines, badCharacterDict,
                            util.ACCEPTED_CHARACTER)
            badLines = []

    def write_bad_lines(badFile, lines, badCharacterDict, goodCharacters):
        """
        write lines to the badFile
        goodCharacters are all allowed Character
        returns all bad Character found in the lines in a list
        """
        for line in lines:
            for character in line:
                if character not in goodCharacters:
                    if character in badCharacterDict.keys():
                        badCharacterDict[character] = badCharacterDict[
                                                          character] + 1
                    else:
                        badCharacterDict[character] = 1
            badFile.write('{0}\n'.format(line))

    def append_hex_ip_line(line):
        nonlocal hexIpRecords
        hexIpRecords.append(line)
        if len(hexIpRecords) >= 10 ** 5:
            writeFiles['hexIpEncoded'].write('\n'.join(hexIpRecords))
            hexIpRecords = []

    def append_good_record(record):
        nonlocal goodRecords, countGoodLines
        goodRecords.append(record)
        countGoodLines = countGoodLines + 1
        add_labels(record)
        if len(record) >= 10 ** 5:
            util.json_dump(record, writeFiles['correct'])
            writeFiles['correct'].write('\n')
            goodRecords = []

    def append_bad_dns_record(record):
        nonlocal badDnsRecords
        badDnsRecords.append(rdnsRecord)
        if len(badDnsRecords) >= 10 ** 5:
            util.json_dump(badDnsRecords, writeFiles['badDNS'])
            writeFiles['badDNS'].write('\n')
            badDnsRecords = []

    lineCount = start
    for line in filepart:
        if len(line) == 0:
            continue
        line = line.strip()
        index = line.find(',')
        if has_bad_characters_for_regex(util.DNS_REGEX, line[(index + 1):]):
            add_bad_line(line)
        else:
            (ipAddress, domain) = split_line(line)
            if is_standart_isp_domain(line, ipregex):
                writeFiles['ipEncoded'].write('{0}\n'.format(line))
            else:
                rdnsRecord = Domain(domain, ip_address=ipAddress)
                if rdnsRecord.domain_labels['tld'].upper() in tlds:
                    if util.is_ip_hex_encoded_simple(ipAddress, domain):
                        append_hex_ip_line(line)
                    else:
                        append_good_record(rdnsRecord)

                else:
                    append_bad_dns_record(rdnsRecord)

        lineCount = lineCount + 1
        if lineCount == end:
            break

    util.json_dump(goodRecords, writeFiles['correct'])
    util.json_dump(badDnsRecords, writeFiles['badDNS'])
    util.json_dump(hexIpRecords, writeFiles['hexIpEncoded'])

    write_bad_lines(writeFiles['bad'], badLines, badCharacterDict, util.ACCEPTED_CHARACTER)

    print('pnr {0}: good lines: {1}'.format(pnr, countGoodLines))
    # with open('rdns_results/{0}-{1}-character.stats'.format(filename, pnr),
    #           'w', encoding='utf-8') as characterStatsFile:
    #     json.dump(badCharacterDict, characterStatsFile)
    with open('rdns_results/{0}-{1}-character.stats'.format(filename, pnr),
              'wb') as characterStatsFile:
        pickle.dump(badCharacterDict, characterStatsFile)

    # with open('rdns_results/{0}-{1}-domain-label.stats'.format(filename, pnr),
    #           'w', encoding='utf-8') as labelStatFile:
    #     json.dump(labelDict, labelStatFile)
    with open('rdns_results/{0}-{1}-domain-label.stats'.format(filename, pnr),
              'wb') as labelStatFile:
        pickle.dump(labelDict, labelStatFile)

    # for character, count in badCharacterDict.items():
    #     print('pnr {0}: Character {1} (unicode: {2}) has {3} occurences'.format(pnr, \
    #         character, ord(character), count))

    writeFiles['correct'].close()
    writeFiles['bad'].close()
    writeFiles['badDNS'].close()
    writeFiles['ipEncoded'].close()
    writeFiles['hexIpEncoded'].close()


if __name__ == '__main__':
    main()
