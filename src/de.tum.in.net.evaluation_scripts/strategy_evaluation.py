#!/usr/bin/env python
"""Evaluation of the different strategies and their difference"""
import argparse
import re
from multiprocessing import Process
import os


def main(args=None):
    """Main"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help='filename to evaluate', type=str)
    parser.add_argument('maxProcesses', default=16, type=int,
                        help='Specify the maximal amount of processes')
    args = parser.parse_args()

    abstractIpregexText = r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),'\
                          r'.*(\1.*\2.*\3.*\4|\4.*\3.*\2.*\1).*$'

    moderateIpregexText = r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),'\
                          r'.*(\1.+\2.+\3.+\4|\4.+\3.+\2.+\1).*$'

    strictIpregexText = r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),'\
                        r'.*(0{0,2}?\1[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\3[\.\-_]'\
                        r'0{0,2}?\4|0{0,2}?\4[\.\-_]0{0,2}?\3[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\1).*$'

    regexes = {}
    regexes['abs'] = re.compile(abstractIpregexText, flags=re.MULTILINE)
    regexes['mod'] = re.compile(moderateIpregexText, flags=re.MULTILINE)
    regexes['str'] = re.compile(strictIpregexText, flags=re.MULTILINE)

    lineCount = 0
    with open(args.filename, 'r', encoding='ISO-8859-1') as fle:

        def line_count(fileToCount):
            """Counts the lines in fileToCount"""
            count = 0
            for _ in fileToCount:
                count = count + 1

            return count

        lineCount = line_count(fle)

    if not os.path.exists('rdns_eval'):
        os.mkdir('rdns_eval')

    partSize = lineCount // args.maxProcesses
    processes = []
    fileIndex = args.filename.find('/')
    filename = args.filename[:]

    while fileIndex >= 0:
        filename = filename[fileIndex + 1:]
        fileIndex = filename.find('/')

    for i in range(0, args.maxProcesses):
        fileHandle = open(args.filename, 'r', encoding='ISO-8859-1')
        process = None
        process = Process(target=evaluate_file_part,
                          args=(filename, i, fileHandle, i * partSize,
                                (i + 1) * partSize, regexes))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()


def evaluate_file_part(filename, pnr, filepart, start, end, regexes):
    """
    Evaluate filepart from start to end
    pnr is a number to recognize the process
    regexes is a dict with 3 keys: 'abs', 'mod' and 'str'. They contain a regex
        object.
    """

    strmodFile = open('rdns_eval/{0}-{1}-nstr.bad'.format(filename, pnr), 'w', encoding='utf-8')
    modabsFile = open('rdns_eval/{0}-{1}-nmod.bad'.format(filename, pnr), 'w', encoding='utf-8')

    def seek_lines(fileToSeek, seekPoint):
        """Read number of lines definded in the seekPoint"""
        i = 0
        if i < seekPoint:
            for _ in fileToSeek:
                i = i + 1
                if i == seekPoint:
                    break

    seek_lines(filepart, start)

    lineCount = start
    for line in filepart:
        if len(line) == 0:
            continue

        if regexes['abs'].search(line) is not None:
            if regexes['mod'].search(line) is not None:
                if regexes['str'].search(line) is None:
                    strmodFile.write(line)
            else:
                modabsFile.write(line)

        if lineCount == end:
            break

    print(pnr, ' finished')


if __name__ == '__main__':
    main()
