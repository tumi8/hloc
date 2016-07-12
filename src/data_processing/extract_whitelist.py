#!/usr/bin/env python3

import argparse
import marisa_trie


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help='filename to sanitize', type=str)
    parser.add_argument('whitelist', help='filename with whitelist', type=str)
    parser.add_argument('-o', '--output-file', dest='output_file', type=str,
                        default='sanitized.out')
    args = parser.parse_args()

    whitelisted = []
    with open(args.whitelist) as whitelist_file:
        for line in whitelist_file:
            whitelisted.append(line.strip())
    whitelist_trie = marisa_trie.Trie(whitelisted)
    with open(args.filename) as sanitize_file, open(args.output_file, 'w') as output_file:
        for line in sanitize_file:
            line = line.strip().split(',')[0]
            if line in whitelist_trie:
                output_file.write(line)

if __name__ == '__main__':
    main()
