#!/usr/bin/env python
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
import json
import pickle
import cProfile
import time
import os
from subprocess import check_output
from string import printable
from multiprocessing import Process


def main(args=None):
    """Main function"""
    start = time.time()
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help='filename to sanitize', type=str)
    parser.add_argument('-n', '--num-processes', default=16, type=int, dest='numProcesses',
                        help='Specify the maximal amount of processes')
    parser.add_argument('-s', '--strategy', type=str, dest='regexStrategy',
                        choices=['strict', 'abstract', 'moderate'], default='abstract',
                        help='Specify a regex Strategy')
    parser.add_argument('-p', '--profile', action='store_true', dest='cProfiling',
                        help='if set the cProfile will profile the script for one process')
    args = parser.parse_args()

    if not os.path.exists('rdns_results'):
        os.mkdir('rdns_results')

    ipregexText = ''
    if args.regexStrategy == 'abstract':
        # most abstract regex
        ipregexText = r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),'\
                r'.*(\1.*\2.*\3.*\4|\4.*\3.*\2.*\1).*$'
    elif args.regexStrategy == 'moderate':
        # slightly stricter regex
        ipregexText = r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),'\
                r'.*(\1.+\2.+\3.+\4|\4.+\3.+\2.+\1).*$'
    elif args.regexStrategy == 'strict':
        # regex with delimiters restricted to '.','-' and '_'
        ipregexText = r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),'\
                r'.*(0{0,2}?\1[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\3[\.\-_]'\
                r'0{0,2}?\4|0{0,2}?\4[\.\-_]0{0,2}?\3[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\1).*$'

    print('using strategy: {}'.format(args.regexStrategy))
    ipregex = re.compile(ipregexText, flags=re.MULTILINE)

    lineCount = 0
    count = check_output(['wc', '-l', args.filename])
    lineCount = int(str(count, encoding='utf-8').split(' ')[0])
    # with open(args.filename, 'r', encoding='ISO-8859-1') as fle:
    #     lineCount = line_count(fle)

    print('Linecount for file: {0}'.format(lineCount))

    tlds = set()
    with open('collectedData/tlds.txt') as tldFile:
        for line in tldFile:
            if line[0] != '#':
                tlds.add(line[:-1])

    tlds.add('edu')
    tlds.add('gov')
    partSize = lineCount // args.numProcesses
    processes = []
    fileIndex = args.filename.find('/')
    filename = args.filename[:]

    while fileIndex >= 0:
        filename = filename[fileIndex + 1:]
        fileIndex = filename.find('/')

    for i in range(0, args.numProcesses):
        fileHandle = open(args.filename, 'r', encoding='ISO-8859-1')
        process = None
        if i == (args.numProcesses - 1):
            process = Process(target=preprocess_file_part_profile,
                              args=(filename, i, fileHandle, i * partSize,
                                    lineCount, ipregex, tlds, args.cProfiling))
        else:
            process = Process(target=preprocess_file_part_profile,
                              args=(filename, i, fileHandle, i * partSize,
                                    (i + 1) * partSize, ipregex, tlds, False))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    end = time.time()
    print('Running time: {0}'.format((end - start)))


def line_count(fileToCount):
    """Counts the lines in fileToCount"""
    count = 0
    for _ in fileToCount:
        count = count + 1

    return count


def preprocess_file_part_profile(filename, pnr, filepart, start, end, ipregex, tlds, profile):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    if profile is set CProfile will profile the sanitizing
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """
    startTime = time.clock()
    if profile:
        cProfile.runctx('preprocess_file_part(filename, pnr, filepart, start, end, ipregex, tlds)',
                        globals(), locals())
    else:
        preprocess_file_part(filename, pnr, filepart, start, end, ipregex, tlds)

    endTime = time.clock()
    print('pnr {0}: preprocess_file_part running time: {1} profiled: {2}'
          .format(pnr, (endTime - startTime), profile))


def preprocess_file_part(filename, pnr, filepart, start, end, ipregex, tlds):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """
    labelDict = {}

    def add_labels(rdnsRecord):
        for key, label in rdnsRecord['domainLabels'].items():
            if key == 'tld':
                continue
            if label in labelDict.keys():
                labelDict[label] = labelDict[label] + 1
            else:
                labelDict[label] = 1

    seek_lines(filepart, start)
    correctFile = open('rdns_results/{0}-{1}.cor'.format(filename, pnr), 'w', encoding='utf-8')
    standartISPnamesFile = open('rdns_results/{0}-{1}-reverse-ip.domain'.format(filename, pnr),
                                'w', encoding='utf-8')
    telekomFile = open('rdns_results/{0}-{1}-hex-ip.domain'.format(filename, pnr),
                       'w', encoding='utf-8')
    badFile = open('rdns_results/{0}-{1}.bad'.format(filename, pnr), 'w', encoding='utf-8')
    badDnsFile = open('rdns_results/{0}-{1}-dns.bad'.format(filename, pnr), 'w', encoding='utf-8')

    goodCharacter = '{0},.-_'.format(printable[0:62])
    dnsregex = re.compile(r'^[a-zA-Z0-9\.\-_]+$', flags=re.MULTILINE)
    badCharacterDict = {}
    badLines = []
    countGoodLines = 0
    goodRecords = []
    badDnsRecords = []
    telekomRecords = []

    lineCount = start
    for line in filepart:
        if len(line) == 0:
            continue
        line = line.strip()
        index = line.find(',')
        if has_bad_characters_for_regex(dnsregex, line[(index + 1):]):
            badLines.append(line)
            if len(badLines) > 10 ** 3:
                badCharacters = write_bad_lines(badFile, badLines, goodCharacter)
                badLines = []
                for character in badCharacters:
                    if character in badCharacterDict.keys():
                        badCharacterDict[character] = badCharacterDict[character] + 1
                    else:
                        badCharacterDict[character] = 1
        else:
            (ipAddress, domain) = split_line(line)
            if is_not_standart_isp_domain(line, ipregex):
                rdnsRecord = {'ip': ipAddress, 'domainLabels': get_domain_labels(domain)}
                if rdnsRecord['domainLabels']['tld'].upper() in tlds:
                    if is_ip_hex_encoded(ipAddress, domain):
                        telekomRecords.append(line)
                        if len(telekomRecords) >= 10 ** 5:
                            telekomFile.write('\n'.join(telekomRecords))
                            telekomRecords = []

                    else:
                        goodRecords.append(rdnsRecord)
                        countGoodLines = countGoodLines + 1
                        add_labels(rdnsRecord)
                        if len(goodRecords) >= 10 ** 5:
                            json.dump(goodRecords, correctFile)
                            correctFile.write('\n')
                            goodRecords = []

                else:
                    badDnsRecords.append(rdnsRecord)
                    if len(badDnsRecords) >= 10 ** 5:
                        json.dump(badDnsRecords, badDnsFile)
                        badDnsFile.write('\n')
                        badDnsRecords = []

            else:
                standartISPnamesFile.write('{0}\n'.format(line))
        lineCount = lineCount + 1
        if lineCount == end:
            break

    json.dump(goodRecords, correctFile)
    json.dump(badDnsRecords, badDnsFile)
    json.dump(telekomRecords, telekomFile)

    badCharacters = write_bad_lines(badFile, badLines, goodCharacter)
    for character in badCharacters:
        if character in badCharacterDict.keys():
            badCharacterDict[character] = badCharacterDict[character] + 1
        else:
            badCharacterDict[character] = 1

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

    correctFile.close()
    badFile.close()
    badDnsFile.close()
    standartISPnamesFile.close()
    telekomFile.close()


def seek_lines(fileToSeek, seekPoint):
    """Read number of lines definded in the seekPoint"""
    i = 0
    if i < seekPoint:
        for _ in fileToSeek:
            i = i + 1
            if i == seekPoint:
                break


def is_ip_hex_encoded(ipAddress, domain):
    """check if the ip address is encoded in hex format in the domain"""
    ip_blocks = ipAddress.split('.')
    hexdata = ''
    for block in ip_blocks:
        hexdata = hexdata + hex(int(block))[2:].zfill(2)

    return hexdata.upper() in domain.upper()


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


def write_bad_lines(badFile, lines, goodCharacters):
    """
    write lines to the badFile
    goodCharacters are all allowed Character
    returns all bad Character found in the lines in a list
    """
    badCharacters = []
    for line in lines:
        for character in line:
            if character not in goodCharacters:
                badCharacters.append(character)
        badFile.write('{0}\n'.format(line))
    return badCharacters


def is_not_standart_isp_domain(line, ipregex):
    """Basic check if the domain is a isp client domain address"""
    return ipregex.search(line) is None


def get_domain_labels(domain):
    """Split domain in to the diffrent levels and save them in a dict"""
    domainLabels = {}
    levels = domain.split('.')[::-1]
    domainLabels['tld'] = levels[0]
    for levelNumber in range(1, len(levels)):
        domainLabels['{0}'.format(levelNumber - 1)] = levels[levelNumber]
    return domainLabels

if __name__ == '__main__':
    main()
