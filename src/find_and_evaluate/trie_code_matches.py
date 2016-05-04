#!/usr/bin/env python3

import pickle
import argparse
from pprint import pprint

from marisa_trie import RecordTrie


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str,
                        help='The filename with the location-trie')
    args = parser.parse_args()

    with open(args.filename, 'rb') as location_file:
        trie = pickle.load(location_file)
    assert isinstance(trie, RecordTrie)

    code_tuples = trie.items()
    matches = {}
    count_top_level_codes = 0

    for code, (location_id,) in code_tuples:
        if location_id not in matches:
            matches[location_id] = {'__total_count__': 0}
        elif code in matches[location_id]:
            continue
        code_matches = set(trie.keys(code))
        code_match_ids = {}
        total_count = 0
        for code_match in code_matches:
            code_match_ids[code_match] = trie[code_match]
            total_count += len(code_match_ids[code_match])
        if len(code_match_ids.keys()) > 1 or len(code_match_ids[code]) > 1:
            count_top_level_codes += 1

        matches[location_id][code] = code_match_ids
        matches[location_id][code]['__total_count__'] = total_count
        matches[location_id]['__total_count__'] += total_count

    loc_id_count = [(loc_id, dct['__total_count__']) for loc_id, dct in matches.items()]
    loc_id_count.sort(key=lambda x: x[1])
    pprint(loc_id_count)
    with open(args.filename + '.eval', 'wb') as eval_file:
        pickle.dump(matches, eval_file)