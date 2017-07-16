#!/usr/bin/env python3

"""
 * Searches for location hints in domain names using a trie data structure
 * Can use 3 types of blacklist to exclude unlikely matches
"""

import collections
import json
import multiprocessing as mp
import datetime
import typing
import marisa_trie

import configargparse

from hloc import util
from hloc.models import CodeMatch, Location, LocationCodeType, Session, Domain, DomainLabel, \
    DomainType, LocationInfo
from hloc.models.location import location_hint_label_table
from hloc.db_utils import get_all_domains_splitted, create_session_for_process

logger = None


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('-p', '--number-processes', type=int, default=4,
                        help='specify the number of processes used')
    parser.add_argument('-c', '--code-blacklist-file', type=str, help='The code blacklist file')
    parser.add_argument('-f', '--word-blacklist-file', type=str, help='The word blacklist file')
    parser.add_argument('-s', '--code-to-location-blacklist-file', type=str,
                        help='The code to location blacklist file')
    parser.add_argument('-a', '--amount', type=int, default=0,
                        help='Specify the amount of dns entries which should be searched'
                             ' per Process. Default is 0 which means all dns entries')
    parser.add_argument('-e', '--exclude-sld', help='Exclude sld from search',
                        dest='exclude_sld', action='store_true')
    parser.add_argument('-n', '--domain-block-limit', type=int, default=10,
                        help='The number of domains taken per block to process them')
    parser.add_argument('--include-ip-encoded', action='store_true',
                        help='Search also domains of type IP encoded')
    parser.add_argument('-l', '--logging-file', type=str, default='find_trie.log',
                        help='Specify a logging file where the log should be saved')
    parser.add_argument('-ll', '--log-level', type=str, default='INFO', dest='log_level',
                        choices=['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the preferred log level')


def main():
    """Main function"""
    parser = configargparse.ArgParser(default_config_files=['find_default.ini'])

    __create_parser_arguments(parser)
    args = parser.parse_args()

    global logger
    logger = util.setup_logger(args.logging_file, 'find', loglevel=args.log_level)

    trie = create_trie(args.code_blacklist_file, args.word_blacklist_file)

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
    for index in range(0, args.number_processes):
        process = mp.Process(target=search_process,
                             args=(index, trie, code_to_location_blacklist, args.exclude_sld,
                                   args.domain_block_limit, args.number_processes,
                                   args.include_ip_encoded),
                             kwargs={'amount': args.amount, 'debug': args.log_level == 'DEBUG'},
                             name='find_locations_{}'.format(index))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()


def create_trie(code_blacklist_filepath: str, word_blacklist_filepath: str):
    """
    Creates a RecordTrie with the marisa library
    :param code_blacklist_filepath: the path to the code blacklist file
    :param word_blacklist_filepath: the path to the word blacklist file
    :rtype: marisa_trie.RecordTrie
    """
    Session = create_session_for_process()
    db_session = Session()
    try:
        locations = db_session.query(LocationInfo)

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

        return create_trie_obj(locations, code_blacklist_set, word_blacklist_set)
    finally:
        db_session.close()
        Session.remove()


def create_trie_obj(location_list: [Location], code_blacklist: {str}, word_blacklist: {str}):
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
        code_id_type_tuples.append((code, ('0'*32, -1)))

    encoded_tuples = [(code, (uid.encode(), code_type))
                      for code, (uid, code_type) in code_id_type_tuples]

    return marisa_trie.RecordTrie('<32sh', encoded_tuples)


def search_process(index, trie, code_to_location_blacklist, exclude_sld, limit, nr_processes,
                   include_ip_encoded, amount=1000, debug: bool=False):
    """
    for all amount=0
    """
    Session = create_session_for_process()
    db_session = Session()

    match_count = collections.defaultdict(int)
    entries_count = 0
    label_count = 0
    entries_wl_count = 0
    label_wl_count = 0
    label_length = 0

    domain_types = [DomainType.valid]
    if include_ip_encoded:
        domain_types.append(DomainType.ip_encoded)

    for domain in get_all_domains_splitted(index, block_limit=limit, nr_processes=nr_processes,
                                           domain_types=domain_types, db_session=db_session):
        loc_found = False

        for i, domain_label in enumerate(domain.labels):
            if i == 0:
                # if tld skip
                continue
            if exclude_sld and i == 1:
                # test for skipping the second level domain
                continue

            if debug:
                last_search = datetime.datetime.now() - datetime.timedelta(minutes=5)
            else:
                last_search = datetime.datetime.now() - datetime.timedelta(days=7)

            label_count += 1
            label_loc_found = False
            label_length += len(domain_label.name)

            if domain_label.last_searched and domain_label.last_searched > last_search:
                if domain_label.hints:
                    label_wl_count += 1

                continue

            pm_count = collections.defaultdict(int)

            domain_label.hints.clear()
            db_session.commit()

            temp_gr_count = search_in_label(domain_label, trie, code_to_location_blacklist,
                                            db_session)

            for key, value in temp_gr_count.items():
                match_count[key] += value
                pm_count[key] += value

            if temp_gr_count:
                label_loc_found = True
                loc_found = True

            if label_loc_found:
                label_wl_count += 1

        if loc_found:
            entries_wl_count += 1

        db_session.commit()
        entries_count += 1

        if entries_count == amount:
            break

        if entries_count == amount:
            break

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
    db_session.close()
    Session.remove()


def search_in_label(label_obj: DomainLabel, trie: marisa_trie.RecordTrie, special_filter,
                    db_session: Session) -> typing.DefaultDict[LocationCodeType, int]:
    """returns all matches for this label"""
    ids = set()
    type_count = collections.defaultdict(int)

    for o_label in label_obj.sub_labels:
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
                if [code_type for _, code_type in matching_locations if code_type == -1]:
                    blacklisted.append(key)
                    continue

                for location_id, code_type in matching_locations:
                    real_code_type = LocationCodeType(code_type)
                    if location_id in ids:
                        continue

                    match = CodeMatch(location_id.decode(), label_obj, code_type=real_code_type,
                                      code=key)
                    db_session.add(match)
                    # label_obj.hints.append(match)
                    type_count[real_code_type] += 1

            label = label[1:]

    label_obj.last_searched = datetime.datetime.now()
    db_session.commit()

    return type_count


if __name__ == '__main__':
    main()
