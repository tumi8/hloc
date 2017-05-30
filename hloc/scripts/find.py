#!/usr/bin/env python3

"""
 * Searches for location hints in domain names using a trie data structure
 * Can use 3 types of blacklist to exclude unlikely matches
"""

import cProfile
import collections
import json
import mmap
import multiprocessing as mp
import time
import marisa_trie

import configargparse

import hloc.json_util as json_util
from hloc import util
from hloc.models import CodeMatch, Location, LocationCodeType

logger = None


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('location_file', type=str, help='The file with the location codes')
    parser.add_argument('-c', '--code-blacklist-file', type=str, help='The code blacklist file')
    parser.add_argument('-f', '--word-blacklist-file', type=str, help='The word blacklist file')
    parser.add_argument('-s', '--code-to-location-blacklist-file', type=str,
                        help='The code to location blacklist file')
    parser.add_argument('doaminfilename_proto', type=str,
                        help='The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string')
    parser.add_argument('-n', '--file-count', type=int, default=8,
                        dest='fileCount',
                        help='number of files from preprocessing')
    parser.add_argument('-a', '--amount-dns-entries', type=int, default=0,
                        dest='amount',
                        help='Specify the amount of dns entries which should be searched'
                             ' per Process. Default is 0 which means all dns entries')
    parser.add_argument('-r', '--profile', help='Profiles process 1 and 7',
                        dest='profile', action='store_true')
    parser.add_argument('-e', '--exclude-sld', help='Exclude sld from search',
                        dest='exclude_sld', action='store_true')
    parser.add_argument('-l', '--logging-file', type=str, default='find_trie.log',
                        help='Specify a logging file where the log should be saved')


def main():
    """Main function"""
    parser = configargparse.ArgParser(default_config_files=['find_default.ini'])

    __create_parser_arguments(parser)
    args = parser.parse_args()

    global logger
    logger = util.setup_logger(args.logging_file, 'find')

    trie = create_trie(args.location_file, args.code_blacklist_file, args.word_blacklist_file)

    code_to_location_blacklist = {}
    if args.code_to_location_blacklist_file:
        with open(args.code_to_location_blacklist_file) as code_to_location_blacklist_file:
            json_txt = ""
            for line in code_to_location_blacklist_file:
                line = line.strip()
                if line[0] != '#':
                    json_txt += line
            code_to_location_blacklist = json.loads(json_txt)

    processes = []
    for index in range(0, args.fileCount):
        # start process for filename.format(0)

        process = mp.Process(target=search_in_file_profile,
                             args=(args.doaminfilename_proto, index, trie,
                                   code_to_location_blacklist, args.exclude_sld, args.profile),
                             kwargs={'amount': args.amount},
                             name='find_locations_{}'.format(index))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()


def create_trie(location_filepath: str, code_blacklist_filepath: str, word_blacklist_filepath: str):
    """
    Creates a RecordTrie with the marisa library
    :param location_filepath: the filepath where the locations are saved
    :param code_blacklist_filepath: the path to the code blacklist file
    :param word_blacklist_filepath: the path to the word blacklist file
    :rtype: marisa_trie.RecordTrie
    """
    with open(location_filepath) as location_file:
        locations = json_util.json_load(location_file)

    code_blacklist_set = set()
    if code_blacklist_filepath:
        with open(code_blacklist_filepath) as code_blacklist_file:
            for line in code_blacklist_file:
                line = line.strip()
                if line[0] != '#':
                    code_blacklist_set.add(line)

    word_blacklist_set = set()
    if word_blacklist_filepath:
        with open(word_blacklist_filepath) as word_blacklist_file:
            for line in word_blacklist_file:
                line = line.strip()
                if line[0] != '#':
                    word_blacklist_set.add(line)

    return create_trie_obj(locations.values(), code_blacklist_set, word_blacklist_set)


def create_trie_obj(location_list: [Location], code_blacklist: [str], word_blacklist: [str]):
    """
    Creates a RecordTrie with the marisa library
    :param location_list: a list with all locations
    :param code_blacklist: a list with all codes to blacklist
    :param word_blacklist: a list with all words which should be blacklisted
    :rtype: marisa_trie.RecordTrie
    """
    code_id_type_tuples = []
    for location in location_list:
        code_id_type_tuples.extend(location.code_id_type_tuples())

    code_id_type_tuples = [code_tuple for code_tuple in code_id_type_tuples
                           if code_tuple[0] not in code_blacklist and
                           code_tuple[0] not in word_blacklist]

    for code in word_blacklist:
        code_id_type_tuples.append((code, (-1, -1)))

    return marisa_trie.RecordTrie('<hh', code_id_type_tuples)


def search_in_file_profile(filename_proto, index, trie, code_to_location_blacklist, exclude_sld,
                           profile, amount=1000):
    """for all amount=0"""
    start_time = time.time()
    if profile and index in [1, 7]:
        cProfile.runctx(
            'search_in_file(filename_proto, index, trie, code_to_location_blacklist, exclude_sld, '
            'amount=amount)',
            globals(), locals())
    else:
        search_in_file(filename_proto, index, trie, code_to_location_blacklist, exclude_sld,
                       amount=amount)
    end_time = time.time()
    logger.info('index {0}: search_in_file running time: {1}'.format(
        index, (end_time - start_time)))


def search_in_file(filename_proto, index, trie, code_to_location_blacklist, exclude_sld,
                   amount=1000):
    """for all amount=0"""
    filename = filename_proto.format(index)
    match_count = collections.defaultdict(int)
    entries_count = 0
    label_count = 0
    entries_wl_count = 0
    label_wl_count = 0
    label_length = 0

    def save_entrie(entrie, entries, entrie_file, new_line=True):
        entries.append(entrie)
        if len(entries) >= 10 ** 3:
            json_util.json_dump(entries, entrie_file)
            if new_line:
                entrie_file.write('\n')
            entries[:] = []

    with open(filename) as dns_file_handle, \
            open('.'.join(filename.split('.')[:-1]) + '-found.json', 'w') as loc_found_file, \
            open('.'.join(filename.split('.')[:-1]) + '-not-found.json', 'w') as locn_found_file, \
            mmap.mmap(dns_file_handle.fileno(), 0, access=mmap.ACCESS_READ) as dns_file:

        def lines(mmap_file: mmap.mmap):
            while True:
                mmap_line = mmap_file.readline().decode('ISO-8859-1')
                if not mmap_line:
                    break
                yield mmap_line

        no_location_found = []
        location_found = []

        for line in lines(dns_file):
            dns_entries = json_util.json_loads(line)

            for domain in dns_entries:
                loc_found = False
                for i, o_label in enumerate(domain.domain_labels):
                    if i == 0:
                        # if tld skip
                        continue
                    if exclude_sld and i == 1:
                        # test for skipping the second level domain
                        continue
                    label_count += 1
                    label_loc_found = False
                    label_length += len(o_label.label)

                    pm_count = collections.defaultdict(int)

                    o_label.matches = []

                    for sub_label in o_label.sub_labels:
                        temp_gr_count, matches = search_in_label(sub_label, trie,
                                                                 code_to_location_blacklist)

                        for key, value in temp_gr_count.items():
                            match_count[key] += value
                            pm_count[key] += value

                        if len(matches) > 0:
                            label_loc_found = True
                            loc_found = True

                        domain.domain_labels[i].matches.append(matches)

                    if label_loc_found:
                        label_wl_count += 1

                if not loc_found:
                    save_entrie(domain, no_location_found, locn_found_file)
                else:
                    entries_wl_count += 1
                    save_entrie(domain, location_found, loc_found_file)

                entries_count += 1

                if entries_count == amount:
                    break

            if entries_count == amount:
                break

        json_util.json_dump(location_found, loc_found_file)
        json_util.json_dump(no_location_found, locn_found_file)
        loc_found_file.write('\n')
        locn_found_file.write('\n')

    def build_stat_string_for_logger():
        """
        Builds a string for the final output
        :returns str: a string with a lot of logging info
        """
        stats_string = 'Stats for this process following:'
        stats_string += '\n\ttotal entries: {}'.format(entries_count)
        stats_string += '\n\ttotal labels: {}'.format(label_count)
        stats_string += '\n\ttotal label length: {}'.format(label_length)
        stats_string += '\n\tentries with location found: {}'.format(entries_wl_count)
        stats_string += '\n\tlabel with location found: {}'.format(label_wl_count)
        stats_string += '\n\tmatches: {}'.format(sum(match_count.values()))
        stats_string += '\n\tmatch count:\n{}'.format(match_count)
        return stats_string

    logger.info(build_stat_string_for_logger())


def search_in_label(o_label: str, trie: marisa_trie.RecordTrie, special_filter):
    """returns all matches for this label"""
    matches = []
    ids = {}
    type_count = collections.defaultdict(int)
    label = o_label[:]
    blacklisted = []
    while label:
        matching_keys = trie.prefixes(label)
        matching_keys.sort(key=len, reverse=True)
        for key in matching_keys:
            if [black_word for black_word in blacklisted if key in black_word]:
                continue

            if key in special_filter and \
                    [black_word for black_word in special_filter[key]
                     if black_word in o_label]:
                continue

            matching_locations = trie[key]
            if [location_id for location_id, _ in matching_locations if location_id == -1]:
                blacklisted.append(key)
                continue
            for location_id, code_type in matching_locations:
                real_code_type = LocationCodeType(code_type)
                if location_id in ids:
                    continue
                matches.append(CodeMatch(location_id, real_code_type, code=key))
                type_count[real_code_type] += 1

        label = label[1:]

    return type_count, matches


if __name__ == '__main__':
    main()
