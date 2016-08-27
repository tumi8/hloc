#!/usr/bin/env python3

# import ujson as json
import pickle
import argparse
import cProfile
import time
import os
import mmap
import ujson as json
import collections
from multiprocessing import Process
import marisa_trie

import src.data_processing.util as util

logger = None


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('doaminfilename_proto', type=str,
                        help='The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string')
    parser.add_argument('trie_file_path', type=str,
                        help='The path to the pickle file with the trie from the'
                             'create_trie script')
    parser.add_argument('-n', '--file-count', type=int, default=8,
                        dest='fileCount',
                        help='number of files from preprocessing')
    parser.add_argument('-a', '--amount-dns-entries', type=int, default=0,
                        dest='amount',
                        help='Specify the amount of dns entries which should be searched'
                             ' per Process. Default is 0 which means all dns entries')
    parser.add_argument('-d', '--load-popular-domain-labels', type=str,
                        dest='popular_labels_l',
                        help='Specify a json file where the results for popular labels'
                             ' are saved')
    parser.add_argument('-p', '--save-popular-domain-labels', type=str,
                        dest='popular_labels_s',
                        help='Specify a json file where popular domain labels'
                             ' are saved and the scripts generates a pickle output file with the'
                             ' results saved')
    parser.add_argument('-r', '--profile', help='Profiles process 1 and 7',
                        dest='profile', action='store_true')
    parser.add_argument('-f', '--general-filter-file', dest='general_filter', type=str)
    parser.add_argument('-s', '--special-filter-file', dest='special_filter', type=str)
    parser.add_argument('-l', '--logging-file', type=str, default='find_trie.log', dest='log_file',
                        help='Specify a logging file where the log should be saved')


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    global logger
    logger = util.setup_logger(args.log_file, 'find')

    with open(args.trie_file_path, 'rb') as trie_file:
        trie = pickle.load(trie_file)

    with open(args.special_filter) as special_filter_file:
        special_filter = json.load(special_filter_file)

    popular_labels = {}
    if args.popular_labels_l is not None:
        with open(args.popular_labels_l) as pop_label_dict:
            popular_labels = json.load(pop_label_dict)

    if args.popular_labels_s is not None:
        with open(args.popular_labels_s) as pop_label_file:
            popular_labels_list = json.load(pop_label_file)

        for label in popular_labels_list:
            if label not in popular_labels.keys():
                popular_labels[label] = {'matches': None}

    processes = []
    for index in range(0, args.fileCount):
        # start process for filename.format(0)

        process = Process(target=start_search_in_file,
                          args=(args.doaminfilename_proto, index, trie,
                                popular_labels, special_filter, args.profile),
                          kwargs={'amount': args.amount},
                          name='find_locations_{}'.format(index))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    popular_labels = {}
    for index in range(0, args.fileCount):
        with open('popular_labels_found_{}.pickle'.format(index),
                  'rb') as popular_file:
            temp = pickle.load(popular_file)
            for key, value in temp.items():
                if key not in popular_labels.keys():
                    popular_labels[key] = value

        os.remove('popular_labels_found_{}.pickle'.format(index))

    with open('popular_labels_found.pickle', 'w') as popular_file:
        json.dump(popular_labels, popular_file)


def start_search_in_file(filename_proto, index, trie, popular_labels, special_filter, profile,
                         amount=1000):
    """for all amount=0"""
    start_time = time.time()
    if profile and index in [1, 7]:
        cProfile.runctx(
            'search_in_file(filename_proto, index, trie, popular_labels, special_filter, '
            'amount=amount)', globals(), locals())
    else:
        search_in_file(filename_proto, index, trie, popular_labels, special_filter, amount=amount)
    end_time = time.time()
    logger.info('index {0}: search_in_file running time: {1}'.format(
        index, (end_time - start_time)))


def search_in_file(filename_proto, index, trie, popular_labels, special_filter, amount=1000):
    """for all amount=0"""
    filename = filename_proto.format(index)
    match_count = collections.defaultdict(int)
    entries_count = 0
    label_count = 0
    entries_wl_count = 0
    label_wl_count = 0
    popular_count = 0
    label_length = 0

    def save_entrie(entrie, entries, entrie_file, new_line=True):
        entries.append(entrie)
        if len(entries) >= 10 ** 4:
            util.json_dump(entries, entrie_file)
            if new_line:
                entrie_file.write('\n')
            entries[:] = []

    # TODO split by dash
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
            dns_entries = util.json_loads(line)

            for domain in dns_entries:
                loc_found = False
                for i, o_label in enumerate(domain.domain_labels):
                    if i == 0:
                        continue
                    label_count += 1
                    label_loc_found = False
                    is_popular = o_label in popular_labels.keys()
                    label_length += len(o_label.label)

                    if is_popular and popular_labels[o_label.label]['matches'] is not None:
                        popular_count += 1
                        domain.domain_labels[i].matches = popular_labels[o_label]['matches'][:]
                        label_loc_found = len(
                            domain.domain_labels[key]['matches']) > 0
                        for key in match_count.keys():
                            match_count[key] += popular_labels[o_label]['counts'][key]
                    else:
                        pm_count = collections.defaultdict(int)

                        temp_gr_count, matches = search_in_label(o_label, trie, special_filter)

                        for key, value in temp_gr_count.items():
                            match_count[key] += value
                            pm_count[key] += value

                        if len(matches) > 0:
                            label_loc_found = True
                            loc_found = True

                        domain.domain_labels[i].matches = matches

                        if is_popular:
                            popular_count += 1
                            popular_labels[o_label.label] = \
                                {
                                    'matches': domain.domain_labels[key]['matches'][:],
                                    'counts': pm_count
                                }

                    if label_loc_found:
                        label_wl_count += 1

                if not loc_found:
                    save_entrie(domain, no_location_found, locn_found_file)
                else:
                    entries_wl_count += 1
                    save_entrie(domain, location_found, loc_found_file)

                entries_count += 1
                # if entries_count % 200 == 0:
                #     print('index ', index, ' at ', entries_count, ' entries')
                if entries_count == amount:
                    break

            if entries_count == amount:
                break

        util.json_dump(location_found, loc_found_file)
        util.json_dump(no_location_found, locn_found_file)

    with open('popular_labels_found_{}.pickle'.format(index),
              'wb') as popular_file:
        pickle.dump(popular_labels, popular_file)
    logger.info('total entries: {}'.format(entries_count))
    logger.info('total labels: {}'.format(label_count))
    logger.info('total label length: {}'.format(label_length))
    logger.info('popular_count: {}'.format(popular_count))
    logger.info('entries with location found: {}'.format(entries_wl_count))
    logger.info('label with location found: {}'.format(label_wl_count))
    logger.info('matches: {}'.format(sum(match_count.values())))
    logger.info('match count:\n{}'.format(match_count))


def search_in_label(o_label: util.DomainLabel, trie: marisa_trie.RecordTrie, special_filter):
    """returns all matches for this label"""
    matches = []
    ids = {}
    type_count = collections.defaultdict(int)
    label = o_label.label[:]
    blacklisted = []
    while label:
        matching_keys = trie.prefixes(label)
        matching_keys.sort(key=len, reverse=True)
        for key in matching_keys:
            if [black_word for black_word in blacklisted if key in black_word]:
                continue

            if key in special_filter and \
                    [black_word for black_word in special_filter[key]
                     if black_word in o_label.label]:
                continue

            matching_locations = trie[key]
            if [location_id for location_id, _ in matching_locations if location_id == -1]:
                blacklisted.append(key)
                continue
            for location_id, code_type in matching_locations:
                real_code_type = util.LocationCodeType(code_type)
                if location_id in ids:
                    continue
                matches.append(util.DomainLabelMatch(location_id, real_code_type,
                                                     domain_label=o_label, code=key))
                type_count[real_code_type] += 1

        label = label[1:]

    return type_count, matches


if __name__ == '__main__':
    main()
