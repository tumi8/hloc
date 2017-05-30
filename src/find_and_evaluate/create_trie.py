#!/usr/bin/env python3

"""

"""

import pickle
import argparse

import marisa_trie
import src.data_processing.util as util


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str,
                        help='The filename with the location codes')
    parser.add_argument('code_black_list', type=str)
    parser.add_argument('-f', '--word-filter-file', dest='general_filter', type=str)
    args = parser.parse_args()

    with open(args.filename) as location_file:
        locations = util.json_load(location_file)

    blacklist = set()
    with open(args.code_black_list) as blacklist_file:
        for line in blacklist_file:
            blacklist.add(line.strip())

    general_filter = set()
    with open(args.general_filter) as general_filter_file:
        for line in general_filter_file:
            general_filter.add(line.strip())

    trie = create_trie(locations, blacklist, general_filter)

    with open('.'.join(args.filename.split('.')[:-1]) + '-trie.pickle',
              'wb') as location_regex_file:
        pickle.dump(trie, location_regex_file)


def create_trie(locations, blacklist, general_filter):
    """
    Creates a RecordTrie with the marisa library
    :rtype: RecordTrie
    """
    code_id_type_tuples = []
    for location in locations.values():
        code_id_type_tuples.extend(location.code_id_type_tuples())

    code_id_type_tuples = [code_tuple for code_tuple in code_id_type_tuples
                           if code_tuple[0] not in blacklist and
                           code_tuple[0] not in general_filter]

    for code in general_filter:
        code_id_type_tuples.append((code, (-1, -1)))

    return marisa_trie.RecordTrie('<hh', code_id_type_tuples)

if __name__ == '__main__':
    main()
