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
    output_file_lock = mp.Lock()
    lines_to_write = []

    def write_wl_lines(to_write):
        with output_file_lock:
            output_file.write(to_write)

    processes = [None] * 8

    for i in range(0, 8):
        processes[i] = mp.Process(target=extract_lines,
                                  args=(i, args.filename, write_wl_lines(), whitelist_trie),
                                  name='extracting_{}'.format(i))

    logging.info('starting processes')

    for process in processes:
        process.start()

    for process in processes:
        process.join()

    my_to_write = '\n'.join(lines_to_write) + '\n'
    output_file.write(my_to_write)
    output_file.close()

    end_time = time.monotonic()
    logging.info('final running time: {}'
                 .format((end_time - start_time)))


BLOCK_SIZE = 100


def extract_lines(pid: int, filename: str, save_func, whitelist_trie):
    logging.info('starting')
    start_time = time.monotonic()
    with open(filename) as sanitize_file:
        seek_before = 0
        seek_after = 0
        lines = 0
        lines_to_write = []

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
                    lines_to_write.append(line)
                    if len(lines_to_write) >= 10 ** 4:
                        to_write = '\n'.join(lines_to_write) + '\n'
                        del lines_to_write[:]
                        save_func(to_write)
            elif seek_after > 0:
                seek_after -= 1

        to_write = '\n'.join(lines_to_write) + '\n'
        del lines_to_write[:]
        save_func(to_write)

    end_time = time.monotonic()
    logging.info('finished with running time: {}'
                 .format((end_time - start_time)))


if __name__ == '__main__':
    main()
