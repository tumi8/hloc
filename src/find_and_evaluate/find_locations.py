#!/usr/bin/env python

# import ujson as json
import pickle
import argparse
import cProfile
import time
import os
from multiprocessing import Process

from ..data_processing import util
from ..data_processing.util import DomainLabel, DomainLabelMatch


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('doaminfilename_proto', type=str,
                        help='The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string')
    parser.add_argument('regexpickle', type=str,
                        help='The path to the pickle file with the regexes from the'
                             'create_location_regex.py script')
    parser.add_argument('-n', '--file-count', type=int, default=8, dest='fileCount',
                        help='number of files from preprocessing')
    parser.add_argument('-a', '--amount-dns-entries', type=int, default=0,
                        dest='amount',
                        help='Specify the amount of dns entries which should be searched'
                             ' per Process. Default is 0 which means all dns entries')
    parser.add_argument('-d', '--load-popular-domain-labels', type=str,
                        dest='popular_labels_l',
                        help='Specify a pickle file where the results for popular labels'
                             ' are saved')
    parser.add_argument('-p', '--save-popular-domain-labels', type=str,
                        dest='popular_labels_s',
                        help='Specify a pickle file where popular domain labels'
                             ' are saved and the scripts generates a pickle output file with the'
                             ' results saved')
    parser.add_argument('-r', '--profile', help='Profiles process 1 and 7',
                        dest='profile', action='store_true')


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    args = parser.parse_args()

    with open(args.regexpickle, 'rb') as locationRegexFile:
        regexes = pickle.load(locationRegexFile)

    popular_labels = {}
    if args.popular_labels_l is not None:
        with open(args.popular_labels_l, 'rb') as pop_label_dict:
            popular_labels = pickle.load(pop_label_dict)

    if args.popular_labels_s is not None:

        with open(args.popular_labels_s, 'rb') as pop_label_file:
            popular_labels_list = pickle.load(pop_label_file)

        for label in popular_labels_list:
            if label not in popular_labels.keys():
                popular_labels[label] = {'matches': None}

    processes = []
    for index in range(0, args.fileCount):
        # start process for filename.format(0)

        process = Process(target=start_search_in_file,
                          args=(args.doaminfilename_proto, index, regexes, popular_labels,
                                args.profile),
                          kwargs={'amount': args.amount})
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    popular_labels = {}
    for index in range(0, args.fileCount):
        with open('popular_labels_found_{}.pickle'.format(index), 'rb') as popular_file:
            temp = pickle.load(popular_file)
            for key, value in temp.items():
                if key not in popular_labels.keys():
                    popular_labels[key] = value

        os.remove('popular_labels_found_{}.pickle'.format(index))

    with open('popular_labels_found.pickle', 'wb') as popular_file:
        pickle.dump(popular_labels, popular_file)


def start_search_in_file(filename_proto, index, regexes, popular_labels, profile, amount=1000):
    """for all amount=0"""
    startTime = time.time()
    if profile and index in [1, 7]:
        cProfile.runctx('search_in_file(filename_proto, index, regexes, popular_labels, '
                        'amount=amount)', globals(), locals())
    else:
        search_in_file(filename_proto, index, regexes, popular_labels, amount=amount)
    endTime = time.time()
    print('index {0}: search_in_file running time: {1}'
          .format(index, (endTime - startTime)))


def search_in_file(filename_proto, index, regexes, popular_labels, amount=1000):
    """for all amount=0"""
    filename = filename_proto.format(index)
    locFoundFile = open('.'.join(filename.split('.')[:-1]) + '_found.json', 'w')
    locnFoundFile = open('.'.join(filename.split('.')[:-1]) + '_not_found.json', 'w')
    match_count = {'iata': 0, 'icao': 0, 'faa': 0, 'clli': 0, 'alt': 0, 'locode': 0}
    entries_count = 0
    label_count = 0
    entries_wl_count = 0
    label_wl_count = 0
    popular_count = 0
    label_length = 0
    sublabel_count = 0

    def save_entrie(entrie, entries, entrie_file, new_line=True):
        entries.append(entrie)
        if len(entries) >= 10 ** 4:
            util.json_dump(entries, entrie_file)
            if new_line:
                entrie_file.write('\n')
            entries[:] = []


    with open(filename, 'r') as dnsFile:
        no_location_found = []
        location_found = []
        for line in dnsFile:
            dns_entries = util.json_loads(line)

            for domain in dns_entries:
                loc_found = False
                for i, o_label in enumerate(domain.domain_labels):
                    if i == 0:
                        continue
                    label_count = label_count + 1
                    label_loc_found = False
                    is_popular = o_label in popular_labels.keys()
                    label_length = label_length + len(o_label)

                    if is_popular and popular_labels[o_label.label]['matches'] is not None:
                        popular_count = popular_count + 1
                        domain.domain_labels[i].matches = popular_labels[o_label]['matches'][:]
                        label_loc_found = len(domain.domain_labels[key]['matches']) > 0
                        for key in match_count.keys():
                            match_count[key] = match_count[key] + \
                                               popular_labels[o_label]['counts'][key]
                    else:
                        pm_count = {'iata': 0, 'icao': 0, 'faa': 0, 'clli': 0, 'alt': 0,
                                    'locode': 0}

                        temp_count, temp_gr_count, matches = search_in_label(o_label, regexes)
                        sublabel_count = sublabel_count + temp_count

                        for key, value in temp_gr_count.items():
                            match_count[key] = match_count[key] + value
                            pm_count[key] = pm_count[key] + value

                        if len(matches) > 0:
                            label_loc_found = True
                            loc_found = True

                        domain.domain_labels[i].matches = matches

                        if is_popular:
                            popular_count = popular_count + 1
                            popular_labels[o_label.label] = \
                                {'matches': domain.domain_labels[key]['matches'][:],
                                 'counts': pm_count}

                    if label_loc_found:
                        label_wl_count = label_wl_count + 1

                if not loc_found:
                    save_entrie(domain, no_location_found, locnFoundFile)
                else:
                    entries_wl_count = entries_wl_count + 1
                    save_entrie(domain, location_found, locFoundFile)

                entries_count = entries_count + 1
                # if entries_count % 200 == 0:
                #     print('index ', index, ' at ', entries_count, ' entries')
                if entries_count == amount:
                    break

            if entries_count == amount:
                break

        util.json_dump(location_found, locFoundFile)
        util.json_dump(no_location_found, locnFoundFile)

    locFoundFile.close()
    locnFoundFile.close()
    with open('popular_labels_found_{}.pickle'.format(index), 'wb') as popular_file:
        pickle.dump(popular_labels, popular_file)
    print('index', index, 'total entries:', entries_count)
    print('index', index, 'total labels:', label_count)
    print('index', index, 'total label length:', label_length)
    print('index', index, 'popular_count:', popular_count)
    print('index', index, 'entries with location found:', entries_wl_count)
    print('index', index, 'label with location found:', label_wl_count)
    print('index', index, 'matches:', sum(match_count.values()))
    print('index', index, 'match count:\n', match_count)


def search_in_label(o_label, regexes):
    """returns all matches for this label"""
    labels = o_label.label.split('-')
    matches = []
    type_count = {'iata': 0, 'icao': 0, 'faa': 0, 'clli': 0, 'alt': 0,
                  'locode': 0}
    count = 0
    for label in labels:
        count = count + 1
        for location_id, regex in regexes:
            reg_matches = regex.search(label)
            if reg_matches is not None:
                group_dict = reg_matches.groupdict()
                group = None
                for group_key, code in group_dict.items():
                    if code is not None:
                        type_count[group_key] = type_count[group_key] + 1
                        group = group_key
                        break

                matches.append(DomainLabelMatch(location_id, group, domain_label=o_label))

    return (count, type_count, matches)

if __name__ == '__main__':
    main()
