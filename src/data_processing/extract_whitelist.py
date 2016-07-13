#!/usr/bin/env python3

import argparse
import marisa_trie
import multiprocessing as mp
import time
import logging


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help='filename to sanitize', type=str)
    parser.add_argument('whitelist', help='filename with whitelist', type=str)
    parser.add_argument('-o', '--output-file', dest='output_file', type=str,
                        default='sanitized.out')
    args = parser.parse_args()
    start_time = time.monotonic()

    logging.basicConfig(filename='extract_whitelist.log', level=logging.DEBUG,
                        format='[%(levelname)s][%(asctime)s]:[%(processName)s] '
                               '%(filename)s:%(lineno)d %(message)s', datefmt='%d.%m %H:%M:%S')

    whitelisted = []
    with open(args.whitelist) as whitelist_file:
        for line in whitelist_file:
            whitelisted.append(line.strip())
    whitelist_trie = marisa_trie.Trie(whitelisted)

    logging.info('finished with trie')

    output_file = open(args.output_file, 'w')
    lines_array_lock = mp.Lock()
    lines_to_write = []

    def add_whitelisted(wlline):
        nonlocal lines_to_write
        with lines_array_lock:
            lines_to_write.append(wlline)
            if len(lines_to_write) >= 10**4:
                to_write = '\n'.join(lines_to_write) + '\n'
                output_file.write(to_write)
                del lines_to_write[:]

    processes = [None] * 8

    for i in range(0, 8):
        processes[i] = mp.Process(target=extract_lines,
                                  args=(i, args.filename, add_whitelisted, whitelist_trie),
                                  name='extracting_{}'.format(i))

    logging.info('starting processes')

    for process in processes:
        process.start()

    for process in processes:
        process.join()

    to_write = '\n'.join(lines_to_write) + '\n'
    output_file.write(to_write)

    end_time = time.monotonic()
    logging.info('final running time: {}'
                 .format((end_time - start_time)))

    output_file.close()


BLOCK_SIZE = 100


def extract_lines(pid: int, filename: str, save_func, whitelist_trie):
    logging.info('starting')
    start_time = time.monotonic()
    with open(filename) as sanitize_file:
        seek_before = 0
        seek_after = 0
        lines = 0

        def prepare():
            nonlocal seek_after
            nonlocal seek_before
            nonlocal lines
            seek_before = BLOCK_SIZE * pid
            seek_after = BLOCK_SIZE * 8 - BLOCK_SIZE * (pid + 1)
            lines = BLOCK_SIZE

        for line in sanitize_file:
            if seek_before == 0 and lines == 0 and seek_after == 0:
                prepare()
            if seek_before > 0:
                seek_before -= 1
            elif lines > 0:
                lines -= 1
                line = line.strip()
                ip = line.split(',')[0]
                if ip in whitelist_trie:
                    save_func(line)
            elif seek_after > 0:
                seek_after -= 1
    end_time = time.monotonic()
    logging.info('finished with running time: {}'
                 .format((end_time - start_time)))


if __name__ == '__main__':
    main()
