#!/usr/bin/env python3

import pickle
import argparse
import collections
from pprint import pprint
import ujson as json

from marisa_trie import RecordTrie


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str,
                        help='The filename with the location-trie')
    parser.add_argument('-cl', action="store_true",
                        help="set if you want the code to location evaluation")
    parser.add_argument('-cc', action="store_true",
                        help="set if you want the code to code evaluation")
    args = parser.parse_args()

    with open(args.filename, 'rb') as location_file:
        trie = pickle.load(location_file)
    assert isinstance(trie, RecordTrie)

    code_tuples = trie.items()
    matches = {}
    count_top_level_codes = 0

    for code, (location_id, type) in code_tuples:
        if location_id not in matches:
            matches[location_id] = {'__all_match_ids__': set(), '__total_count__': 0} # TODO defaultdict
        elif code in matches[location_id]:
            continue
        code_matches = set(trie.keys(code))
        code_match_ids = {}
        total_count = 0
        for code_match in code_matches:
            code_match_ids[code_match] = trie[code_match]
            for loc_id, _ in code_match_ids[code_match]:
                matches[location_id]['__all_match_ids__'].add(loc_id)
            total_count += len(code_match_ids[code_match])
        if not code_match_ids or list(code_match_ids.keys()) == [code]:
            count_top_level_codes += 1

        matches[location_id][code] = code_match_ids
        matches[location_id][code]['__total_count__'] = total_count
        matches[location_id]['__total_count__'] += total_count

    print(len(matches))
    loc_id_count = [(loc_id, len(dct['__all_match_ids__'])) for loc_id, dct in matches.items()]
    loc_id_count.sort(key=lambda x: x[1])
    #pprint(loc_id_count)

    with open(args.filename + '.cdfdata', 'w') as cdf_file:
        print(args.cc)
        if args.cc:
            json.dump(make_cdf_code_to_code(matches), cdf_file)
        elif args.cl:
            json.dump(make_cdf_code_to_location(matches), cdf_file)
        else:
            json.dump(make_cdf_location_to_location(matches), cdf_file)
    with open(args.filename + '.eval', 'w') as eval_file:
        json.dump(matches, eval_file)


def make_cdf_code_to_code(matches):
    match_count_group = {}
    for dct in matches.values():
        for indct in dct.values():
            if isinstance(indct, int):
                continue
            if indct['__total_count__'] not in match_count_group:
                match_count_group[indct['__total_count__']] = 0
            match_count_group[indct['__total_count__']] += 1
    return match_count_group

def make_cdf_code_to_location(matches):
    match_count_group = {}
    for dct in matches.values():
        for indct in dct.values():
            pprint(indct)
            break
            if isinstance(indct, int):
                continue
            if indct['__total_count__'] not in match_count_group:
                match_count_group[indct['__total_count__']] = 0
            match_count_group[indct['__total_count__']] += 1
        break
    return match_count_group

def make_cdf_location_to_location(matches):
    match_count_group = {}
    for dct in matches.values():
        if len(dct['__all_match_ids__']) not in match_count_group:
            match_count_group[len(dct['__all_match_ids__'])] = 0
        match_count_group[len(dct['__all_match_ids__'])] += 1
    return match_count_group

if __name__ == '__main__':
    main()
