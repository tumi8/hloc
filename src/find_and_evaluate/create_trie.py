#!/usr/bin/env python3

import pickle
import argparse

from marisa_trie import RecordTrie
from ..data_processing import util


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str,
                        help='The filename with the location codes')
    args = parser.parse_args()

    with open(args.filename) as location_file:
        locations = util.json_load(location_file)

    trie = create_trie(locations)

    with open('.'.join(args.filename.split('.')[:-1]) + '-trie.pickle',
              'wb') as location_regex_file:
        pickle.dump(trie, location_regex_file)


def create_trie(locations):
    """
    Creates a RecordTrie with the marisa library
    :rtype: RecordTrie
    """
    code_id_tuples = []
    for location in locations.values():
        code_id_tuples.extend(location.code_id_tuples())

    return RecordTrie('<H', code_id_tuples)

if __name__ == '__main__':
    main()
