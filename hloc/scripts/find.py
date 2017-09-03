#!/usr/bin/env python3

"""
 * Searches for location hints in domain names using a trie data structure
 * Can use 3 types of blacklist to exclude unlikely matches
"""

import collections
import json
import multiprocessing as mp
import threading
import datetime
import typing
import marisa_trie
import queue

import configargparse

from hloc import util
from hloc.models import CodeMatch, Location, LocationCodeType, DomainLabel, \
    DomainType, LocationInfo
from hloc.models.location import location_hint_label_table
from hloc.db_utils import get_all_domains_splitted_efficient, create_session_for_process

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
    parser.add_argument('-n', '--domain-block-limit', type=int, default=1000,
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

    location_match_queue = mp.Queue()
    stop_event = threading.Event()
    handle_location_matches_thread = threading.Thread(target=handle_location_matches,
                                                      name='handle-location-matches',
                                                      args=(location_match_queue, stop_event))
    handle_location_matches_thread.start()

    update_label_queue = mp.Queue()
    update_label_thread = threading.Thread(target=update_labels, name='update-label-search-date',
                                           args=(update_label_queue, stop_event))
    update_label_thread.start()

    processes = []
    for index in range(0, args.number_processes):
        process = mp.Process(target=search_process,
                             args=(index, trie, code_to_location_blacklist, args.exclude_sld,
                                   args.domain_block_limit, args.number_processes,
                                   args.include_ip_encoded, location_match_queue,
                                   update_label_queue),
                             kwargs={'amount': args.amount, 'debug': args.log_level == 'DEBUG'},
                             name='find_locations_{}'.format(index))
        process.start()
        processes.append(process)

    for process in processes:
        process.join()

    stop_event.set()
    update_label_thread.join()
    update_label_queue.join_thread()
    handle_location_matches_thread.join()
    location_match_queue.join_thread()


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


def handle_location_matches(location_match_queue: mp.Queue, stop_event: threading.Event):
    class LocationMatch:
        def __init__(self, location_hint):
            self.id = 0
            self.location_hint = location_hint
            self.location_code = location_hint.code
            self.location_code_type = location_hint.code_type
            self.location_id = location_hint.location_id
            self.domain_label_ids = set()
            self.old_domain_label_ids = set()

        def get_insert_values(self):
            return [{'location_hint_id': self.id,
                     'domain_label_id': domain_label_id}
                    for domain_label_id in self.domain_label_ids]

        def add_domain_label_id(self, domain_label_id):
            if domain_label_id not in self.domain_label_ids and \
                    domain_label_id not in self.old_domain_label_ids:
                self.domain_label_ids.add(domain_label_id)

        def handled_domains(self):
            self.old_domain_label_ids = self.old_domain_label_ids.union(self.domain_label_ids)
            self.domain_label_ids.clear()

        def __hash__(self):
            return hash(make_location_hint_key(self.location_id, self.location_code,
                                               self.location_code_type))

    def make_location_hint_key(location_id, code, code_type):
        return '{},{},{}'.format(location_id, code, code_type)

    def save(matches_to_save, new_matches, db_sess):
        if new_matches:
            db_sess.bulk_save_objects([match.location_hint for match in new_matches],
                                      return_defaults=True)
            for new_match in new_matches:
                new_match.id = new_match.location_hint.id

        insert_values = []
        for match in matches_to_save:
            insert_values.extend(match.get_insert_values())
            match.handled_domains()

        new_matches.clear()
        matches_to_save.clear()

        if insert_values:
            insert_expr = location_hint_label_table.insert().values(insert_values)
            db_sess.execute(insert_expr)

    Session = create_session_for_process()
    db_session = Session()

    new_matches = []
    matches_to_save = set()
    location_hints = {}
    counter = 0
    ccounter = 0

    while not (stop_event.is_set() and location_match_queue.empty()):
        try:
            location_matches_tuples = location_match_queue.get(timeout=1)
            if isinstance(location_matches_tuples, int):
                delete_expr = location_hint_label_table.delete().where(
                    'location_hint_labels.domain_label_id' == location_matches_tuples)
                db_session.execute(delete_expr)
                logger.debug('saving for {}'.format(location_matches_tuples))
            else:
                for location_id, location_code, location_code_type, domain_label_id in \
                        location_matches_tuples:
                    logger.debug('inserting elem for {}'.format(domain_label_id))
                    location_hint_key = make_location_hint_key(location_id, location_code,
                                                               location_code_type)
                    try:
                        location_hint = location_hints[location_hint_key]
                    except KeyError:
                        real_code_type = LocationCodeType(location_code_type)
                        location_hint_obj = CodeMatch(location_id, code_type=real_code_type,
                                                      domain_label=None, code=location_code)
                        db_session.add(location_hint_obj)
                        location_hint = LocationMatch(location_hint_obj)
                        location_hints[location_hint_key] = location_hint
                        new_matches.append(location_hint)

                    matches_to_save.add(location_hint)
                    location_hint.add_domain_label_id(domain_label_id)

                    counter += 1
                    if counter >= 10 ** 4:
                        logger.debug('saving')
                        save(matches_to_save, new_matches, db_session)
                        counter = 0

                        ccounter += 1
                        if ccounter >= 10:
                            db_session.commit()
                            ccounter = 0

        except queue.Empty:
            pass

    save(matches_to_save, new_matches, db_session)
    db_session.commit()
    db_session.close()
    Session.remove()
    location_match_queue.close()
    logger.info('stopped')


def update_labels(label_queue: mp.Queue, stop_event: threading.Event):
    Session = create_session_for_process()
    db_session = Session()
    deleted_ids = set()

    while not (stop_event.is_set() and label_queue.empty()):
        try:
            label_id = label_queue.get(timeout=1)

            if label_id in deleted_ids:
                continue

            deleted_ids.add(label_id)
            label = db_session.query(DomainLabel).filter_by(id=label_id).first()
            if label:
                label.last_searched = datetime.datetime.now()
                db_session.commit()
            else:
                logger.error('label id {} received but could not be found in database'.format(
                    label_id))
        except queue.Empty:
            pass

    db_session.close()
    Session.remove()
    label_queue.close()


def search_process(index, trie, code_to_location_blacklist, exclude_sld, limit, nr_processes,
                   include_ip_encoded, location_match_queue, update_label_queue,
                   amount=1000, debug: bool=False):
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

    if debug:
        last_search = datetime.datetime.now() - datetime.timedelta(minutes=1)
    else:
        last_search = datetime.datetime.now() - datetime.timedelta(days=7)

    for domain in get_all_domains_splitted_efficient(index,
                                                     block_limit=limit,
                                                     nr_processes=nr_processes,
                                                     domain_types=domain_types,
                                                     db_session=db_session):
        loc_found = False

        for i, domain_label in enumerate(domain.labels):
            if i == 0:
                # if tld skip
                continue
            if exclude_sld and i == 1:
                # test for skipping the second level domain
                continue

            label_count += 1
            label_loc_found = False
            label_length += len(domain_label.name)

            if domain_label.last_searched:
                if domain_label.last_searched > last_search:
                    if domain_label.hints:
                        label_wl_count += 1

                    continue
                else:
                    location_match_queue.put(domain_label.id)

            pm_count = collections.defaultdict(int)

            temp_gr_count = search_in_label(domain_label, trie, code_to_location_blacklist,
                                            location_match_queue, update_label_queue)

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
        stats_string += '\n\tmatch count:\n\t\t{}'.format(match_count)
        return stats_string

    logger.info(build_stat_string_for_logger())
    db_session.close()
    Session.remove()
    update_label_queue.close()
    location_match_queue.close()


def search_in_label(label_obj: DomainLabel, trie: marisa_trie.RecordTrie, special_filter,
                    location_match_queue: mp.Queue, update_label_queue: mp.Queue) \
        -> typing.DefaultDict[LocationCodeType, int]:
    """returns all matches for this label"""
    ids = set()
    type_count = collections.defaultdict(int)

    location_hint_tuples = []

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

                    location_hint_tuples.append((location_id.decode(), key, code_type,
                                                 label_obj.id))
                    type_count[real_code_type] += 1

            label = label[1:]

    location_match_queue.put(location_hint_tuples)
    update_label_queue.put(label_obj.id)

    return type_count


if __name__ == '__main__':
    main()
