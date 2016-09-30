#!/usr/bin/env python3
"""
This module checks the location information found with different verifing methods
"""
import argparse
import requests
import time
import os.path
import geoip2.database
import random
import mmap
import IP2Location
import collections
import multiprocessing as mp
import ripe.atlas.cousteau as ripe_atlas
import ripe.atlas.cousteau.exceptions
import threading
import math
import pympler.asizeof
import gc

import src.data_processing.util as util

API_KEY = '1dc0b3c2-5e97-4a87-8864-0e5a19374e60'
RIPE_SESSION = requests.Session()
MAX_RTT = 9
ALLOWED_MEASUREMENT_AGE = 60 * 60 * 24 * 350  # 350 days in seconds
ATLAS_API_URL = 'https://atlas.ripe.net/api/v1/'
API_MEASUREMENT_ENDPOINT = 'measurement'
MEASUREMENT_URL = ATLAS_API_URL + API_MEASUREMENT_ENDPOINT + '/'

LOCATION_RADIUS = 100
LOCATION_RADIUS_PRECOMPUTED = (LOCATION_RADIUS / 6371) ** 2
DISTANCE_METHOD = util.GPSLocation.gps_distance_equirectangular

MAX_THREADS = 20
logger = None
# memory_tracker = pympler.tracker.SummaryTracker()
gc.set_debug(gc.DEBUG_UNCOLLECTABLE)


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string')
    parser.add_argument('-f', '--file-count', type=int, default=8,
                        dest='fileCount',
                        help='number of files from preprocessing')
    parser.add_argument('-loc', '--location-file-name', required=True, type=str,
                        dest='locationFile',
                        help='The path to the location file.'
                             ' The output file from the codes_parser')
    parser.add_argument('-m', '--method', type=str, dest='verifingMethod',
                        choices=['geoip', 'ip2location', 'ripe'],
                        default='ripe',
                        help='Specify the method with wich the locations should be checked')
    # parser.add_argument('-d', '--ripe-node-distance', type=int, dest='ripeDistance',
    #                     default=250, help='This number defines the maximum distance between'
    #                     ' a ripe probe and the suspected location.')
    parser.add_argument('-g', '--geoip-database', type=str, dest='geoipFile',
                        help='If you choose the geoip method you have to'
                             ' specify the path to the database in this argument')
    parser.add_argument('-i', '--ip2location-database', type=str,
                        dest='ip2locFile',
                        help='If you choose the ip2location as method you have to'
                             ' specify the path to the database in this argument.\n'
                             'Currently not tested, because no database is available')
    parser.add_argument('-v', '--ip-version', type=str, dest='ip_version',
                        default=util.IPV4_IDENTIFIER,
                        choices=[util.IPV4_IDENTIFIER, util.IPV6_IDENTIFIER],
                        help='specify the ipVersion')
    ripe_group = parser.add_argument_group('RIPE method arguments')
    ripe_group.add_argument('-z', '--zmap-file', type=str, dest='zmap_filename',
                            help='The results of the zmap scan of the ip addresses')
    ripe_group.add_argument('-q', '--ripe-request-limit', type=int,
                            dest='ripeRequestLimit',
                            help='How many request should normally be allowed per second '
                                 'to the ripe server', default=25)
    ripe_group.add_argument('-b', '--ripe-request-burst-limit', type=int,
                            dest='ripeRequestBurstLimit',
                            help='How many request should at maximum be allowed per second'
                                 ' to the ripe server', default=40)
    ripe_group.add_argument('-ml', '--measurement-limit', type=int, dest='ripe_measurement_limit',
                            help='The amount of parallel RIPE Atlas measurements allowed',
                            default=100)
    ripe_group.add_argument('-raak', '--ripe-atlas-api-key', type=str, dest='api_key',
                            help='The RIPE Atlas Api key',
                            default='1dc0b3c2-5e97-4a87-8864-0e5a19374e60')
    ripe_group.add_argument('-rabt', '--ripe-atlas-bill-to', type=str, dest='bill_to',
                            help='The RIPE Atlas Bill to address')
    ripe_group.add_argument('-d', '--dry-run', action='store_true', dest='dry_run',
                            help='Turns on dry run which returns after the first time coputing '
                                 'the amount of matches to check')
    ripe_group.add_argument('-a', '--append-to-existing', action='store_true', dest='append',
                            help='Tun on if there are matches already existing and you do not want '
                                 'to overwrite them')
    parser.add_argument('-l', '--logging-file', type=str, default='check_locations.log',
                        dest='log_file',
                        help='Specify a logging file where the log should be saved')
    parser.add_argument('-ll', '--log-level', type=str, default='INFO', dest='log_level',
                        choices=['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the preferred log level')


def __check_args(args):
    """Checks arguments validity"""
    if args.filename_proto.find('{}') < 0:
        raise ValueError(
            'Wrong format for the filename! It must be formatable with the '
            '{}-brackets where the numbers have to be inserted.')

    if args.verifingMethod == 'geoip':
        if args.geoipFile is None:
            raise ValueError(
                'Please specify the file location of the geoip database!')
        if not os.path.isfile(args.geoipFile):
            raise ValueError('Path to geoip database does not exist!')

    if args.verifingMethod == 'ip2location':
        if args.ip2locFile is None:
            raise ValueError(
                'Please specify the file location of the ip2lcation database!')
        if not os.path.isfile(args.ip2locFile):
            raise ValueError('Path to ip2location database does not exist!')


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()
    __check_args(args)

    global logger
    logger = util.setup_logger(args.log_file, 'check', loglevel=args.log_level)
    logger.debug('starting')

    start_time = time.time()
    with open(args.locationFile) as locationFile:
        locations = util.json_load(locationFile)

    ripe_create_sema = None
    ripe_slow_down_sema = None
    generator_thread = None
    zmap_results = None
    zmap_locations = None
    distances = None
    finish_event = None
    if args.verifingMethod == 'ripe':
        ripe_slow_down_sema = mp.BoundedSemaphore(args.ripeRequestBurstLimit)
        ripe_create_sema = mp.Semaphore(args.ripe_measurement_limit)
        global API_KEY, MAX_THREADS
        API_KEY = args.api_key
        if args.log_level == 'DEBUG':
            MAX_THREADS = 1
        else:
            MAX_THREADS = int(args.ripe_measurement_limit * 0.2)
        finish_event = threading.Event()
        generator_thread = threading.Thread(target=generate_ripe_request_tokens,
                                            args=(ripe_slow_down_sema, args.ripeRequestLimit,
                                                  finish_event))

        if not args.dry_run:
            if next(iter(locations.values())).nodes is None:
                logger.info('Getting the nodes from RIPE Atlas')
                probe_slow_down_sema = mp.BoundedSemaphore(args.ripeRequestBurstLimit)
                probes_finish_event = threading.Event()
                probes_generator_thread = threading.Thread(target=generate_ripe_request_tokens,
                                                           args=(probe_slow_down_sema,
                                                                 args.ripeRequestLimit,
                                                                 probes_finish_event))
                probes_generator_thread.start()
                thread_sema = threading.Semaphore(10)
                threads = []
                for location in locations.values():
                    if len(threads) > 10:
                        for thread in threads:
                            if not thread.is_alive():
                                thread.join()
                    thread_sema.acquire()
                    thread = threading.Thread(target=get_nearest_ripe_nodes,
                                              args=(location, 1000, args.ip_version,
                                                    probe_slow_down_sema, thread_sema))
                    thread.start()
                    threads.append(thread)

                for thread in threads:
                    thread.join()
                probes_finish_event.set()
                probes_generator_thread.join()

                with open(args.locationFile, 'w') as locationFile:
                    util.json_dump(locations, locationFile)

            null_locations = []
            for location in locations.values():
                if not location.available_nodes:
                    null_locations.append(location)

            logger.info('{} locations without nodes'.format(len(null_locations)))
            with open('locations_wo_nodes.json', 'w') as loc_wo_nodes_file:
                util.json_dump(null_locations, loc_wo_nodes_file)

        if args.zmap_filename:
            with open(args.zmap_filename) as zmap_file:
                location_line = zmap_file.readline()
                results_line = zmap_file.readline()

            zmap_locations = util.json_loads(location_line)
            zmap_results = util.json_loads(results_line)
            del location_line
            del results_line
        else:
            logger.critical('No zmap results file! Aborting!')
            return 1

        distances = init_coords_distances(zmap_locations, locations)

    logger.debug('Size of locations: {}'.format(pympler.asizeof.asizeof(locations)))
    logger.debug('Size of zmap results: {}'.format(pympler.asizeof.asizeof(zmap_results)))
    logger.debug('finished ripe')

    processes = []
    file_count = args.fileCount
    if args.log_level == 'DEBUG':
        file_count = 1
    for pid in range(0, file_count):
        process = None
        if args.verifingMethod == 'ripe':
            process = mp.Process(target=ripe_check_for_list,
                                 args=(args.filename_proto,
                                       pid,
                                       locations,
                                       zmap_locations,
                                       zmap_results,
                                       distances,
                                       ripe_create_sema,
                                       ripe_slow_down_sema,
                                       args.ip_version,
                                       args.dry_run,
                                       args.append,
                                       args.bill_to),
                                 name='domain_checking_{}'.format(pid))
        elif args.verifingMethod == 'geoip':
            process = mp.Process(target=geoip_check_for_list,
                                 args=(args.filename_proto,
                                       pid,
                                       locations,
                                       args.geoipFile),
                                 name='domain_checking_{}'.format(pid))
        elif args.verifingMethod == 'ip2location':
            process = mp.Process(target=ip2location_check_for_list,
                                 args=(args.filename_proto,
                                       pid,
                                       locations,
                                       args.ip2locFile),
                                 name='domain_checking_{}'.format(pid))
        processes.append(process)

    for process in processes:
        process.start()

    if args.verifingMethod == 'ripe':
        generator_thread.start()

    alive = 8
    while alive > 0:
        try:
            process_sts = [pro.is_alive() for pro in processes]
            if process_sts.count(True) != alive:
                alive = process_sts.count(True)
                logger.debug('{} processes alive'.format(alive))
            for process in processes:
                process.join()
        except KeyboardInterrupt:
            pass

    finish_event.set()
    generator_thread.join()
    logger.debug('{} processes alive'.format(alive))
    end_time = time.time()
    logger.info('running time: {}'.format((end_time - start_time)))
    return 0


def init_coords_distances(zmap_locations: [str, util.GPSLocation],
                          code_locations: [str, util.Location]):
    """computes all distances to all locations before the execution starts"""
    distances = {}
    for zmap_id in zmap_locations.keys():
        distances[zmap_id] = {}

    for location_id, location in code_locations.items():
        for zmap_id, zmap_location in zmap_locations.items():
            distances[zmap_id][location_id] = DISTANCE_METHOD(location, zmap_location)

    logger.debug('Size of distances: {}'.format(pympler.asizeof.asizeof(distances)))

    return distances


def generate_ripe_request_tokens(sema: mp.Semaphore, limit: int, finish_event: threading.Event):
    """
    Generates RIPE_REQUESTS_PER_SECOND tokens on the Semaphore
    """
    logger.debug('generate thread started')
    while not finish_event.is_set():
        time.sleep(2 / limit)
        try:
            sema.release()
            sema.release()
        except ValueError:
            continue
    logger.debug('generate thread stoopped')


# TODO falsify databases with all measurements

def ip2location_check_for_list(filename_proto: str, pid: int, locations: [str, util.Location],
                               ip2locations_filename: str):
    """Verifies the locations with the ip2locations database"""
    ip2loc_obj = IP2Location.IP2Location()
    ip2loc_obj.open(ip2locations_filename)

    location_domain_file = open(filename_proto.format(pid) + '.locations', 'w')

    correct_count = collections.defaultdict(int)

    with open(filename_proto.format(pid)) as domainFile:
        domain_file_mm = mmap.mmap(domainFile.fileno(), 0, access=mmap.ACCESS_READ)
        line = domain_file_mm.readline().decode('utf-8')
        while len(line) > 0:
            domain_location_list = util.json_loads(line)
            correct_locs = []
            wrong_locs = []
            for domain in domain_location_list:
                location_label_match = ip2loc_get_domain_location(domain,
                                                                  ip2loc_obj,
                                                                  locations,
                                                                  correct_count)
                if location_label_match is not None:
                    domain.location_match = location_label_match
                    correct_locs.append(domain)
                else:
                    wrong_locs.append(domain)
            util.json_dump(correct_locs, location_domain_file)
            location_domain_file.write('\n')
            line = domain_file_mm.readline().decode('utf-8')


def ip2loc_get_domain_location(domain: util.Domain, ip2loc_reader: IP2Location.IP2Location,
                               locations: [str, util.Location],
                               correct_count: [util.DomainType, int]):
    """checks the domains locations with the geoipreader"""
    ip_location = ip2loc_reader.get_all(domain.ip_address)
    for i, label in enumerate(domain.domain_labels):
        if i == 0:
            # skip if tld
            continue

        for match in label.matches:
            if ip_location.country_short == locations[str(match.location_id)].stateCode:
                correct_count[match.code_type] += 1
                return match

    return None


def geoip_check_for_list(filename_proto, pid, locations, geoip_filename, ip_version: str):
    """Verifies the location with the geoip database"""
    geoipreader = geoip2.database.Reader(geoip_filename)

    correct_count = collections.defaultdict(int)

    with open(filename_proto.format(pid)) as domainFile, \
            mmap.mmap(domainFile.fileno(), 0, access=mmap.ACCESS_READ) as domain_file_mm, \
            open(util.remove_file_ending(filename_proto.format(pid)) +
                 '.geoiplocations', 'w') as location_domain_file:
        line = domain_file_mm.readline().decode('utf-8')
        while len(line) > 0:
            domain_location_list = util.json_loads(line)
            for domain in domain_location_list:
                geoip_get_domain_location(domain, geoipreader, locations, correct_count, ip_version)
            util.json_dump(domain_location_list, location_domain_file)
            location_domain_file.write('\n')
            line = domain_file_mm.readline().decode('utf-8')

    location_domain_file.close()
    geoipreader.close()
    logger.info('correct count: {}'.format(correct_count))


def geoip_get_domain_location(domain, geoipreader, locations, correct_count, ip_version: str):
    """checks the domains locations with the geoipreader"""
    ip_address = domain.ip_for_version(ip_version)
    geoip_location = geoipreader.city(ip_address)
    if geoip_location.location is None or geoip_location.location.longitude is None or \
            geoip_location.location.latitude is None:
        return False

    for match in domain.all_matches:
        location = locations[str(match.location_id)]
        distance = location.gps_distance_equirectangular(
            util.GPSLocation(geoip_location.location.latitude,
                             geoip_location.location.longitude))
        if distance < 100:
            correct_count[match['type']] += 1
            domain.location = locations[str(match.location_id)]
            match.matching = True
            match.matching_distance = distance
            match.matching_rtt = -1
            return True

    return False


def ripe_check_for_list(filename_proto: str, pid: int, locations: [str, util.Location],
                        zmap_locations: [str, util.GPSLocation], zmap_results: [str, [str, float]],
                        distances: [str, [str, float]], ripe_create_sema: mp.Semaphore,
                        ripe_slow_down_sema: mp.Semaphore, ip_version: str, dry_run: bool,
                        append: bool, bill_to_address: str=None):
    """Checks for all domains if the suspected locations are correct"""
    count_lock = threading.Lock()
    correct_type_count = collections.defaultdict(int)

    # chair_server_locks = {'m': threading.Lock(), 's': threading.Lock(), 'd': threading.Lock()}

    domain_lock = threading.Lock()
    domains = collections.defaultdict(list)

    dry_run_count = 0
    dry_run_count_lock = threading.Lock()
    dry_run_matches = []
    dry_run_veri_lock = threading.Lock()
    dry_run_verifications = 0

    count_matches = 0

    file_ending = 'dryrun.matches'

    if not dry_run:
        del dry_run_count
        del dry_run_count_lock
        del dry_run_matches
        del dry_run_verifications
        del count_matches
        file_ending = 'checked'

    file_mode = 'w'
    append_entries = 0
    if append:
        file_mode = 'a'
        append_entries = util.count_lines(util.remove_file_ending(filename_proto).format(pid) +
                                          '.' + file_ending) * 1000

    with open(util.remove_file_ending(filename_proto).format(pid) + '.' + file_ending,
              file_mode) as output_file:

        def update_count_for_type(ctype: util.LocationCodeType):
            """acquires lock and increments in count the type property"""
            with count_lock:
                correct_type_count[ctype.name] += 1

        def increment_dry_run_verifications():
            with dry_run_veri_lock:
                nonlocal dry_run_verifications
                dry_run_verifications += 1

        def add_dry_run_matches(dry_run_rest: [object]):
            """aquires the dry run lock and increments the amount of matches by count"""
            with dry_run_count_lock:
                nonlocal dry_run_count
                dry_run_matches.extend(dry_run_rest)
                dry_run_count += len(dry_run_rest)
                if len(dry_run_matches) >= 10**3:
                    dump_dry_run_matches()

        def dump_dry_run_matches():
            """Write all domains in the buffer to the file and empty the lists"""
            util.json_dump(dry_run_matches, output_file)
            output_file.write('\n')
            dry_run_matches.clear()

        def dump_domain_list(domain_list):
            """Write all domains in the buffer to the file and empty the lists"""
            logger.info('correct {} no_verification {} not_responding {} no_location {} '
                        'blacklisted {}'.format(len(domain_list[util.DomainType.correct]),
                                                len(domain_list[util.DomainType.no_verification]),
                                                len(domain_list[util.DomainType.not_responding]),
                                                len(domain_list[util.DomainType.no_location]),
                                                len(domain_list[util.DomainType.blacklisted])))
            dump_dct = {}
            for result_type, values in domain_list.items():
                dump_dct[result_type.value] = values
            util.json_dump(dump_dct, output_file)
            output_file.write('\n')
            domain_list.clear()

        def update_domains(update_domain: util.Domain, dtype: util.DomainType):
            """Append current domain in the domain dict to the dtype"""
            if dtype == util.DomainType.not_responding:
                nonlocal count_unreachable
                count_unreachable += 1
            elif dtype == util.DomainType.correct and dry_run:
                increment_dry_run_verifications()
            elif dry_run:
                nonlocal count_matches
                count_matches += update_domain.matches_count

            if not dry_run:
                with domain_lock:
                    domains[dtype].append(update_domain)

                    if (len(domains[util.DomainType.correct]) +
                            len(domains[util.DomainType.not_responding]) +
                            len(domains[util.DomainType.no_location]) +
                            len(domains[util.DomainType.blacklisted]) +
                            len(domains[util.DomainType.no_verification])) >= 10**3:
                        dump_domain_list(domains)

        threads = []
        count_entries = 0
        count_unreachable = 0
        skipped_entries = 0

        try:
            with open(filename_proto.format(pid)) as domainFile, \
                    mmap.mmap(domainFile.fileno(), 0, access=mmap.ACCESS_READ) as domain_file_mm:

                domain_location_list = []
                domain_location_list_lock = threading.Lock()

                def next_domains():
                    line = domain_file_mm.readline().decode('utf-8')
                    if line:
                        nonlocal domain_location_list, skipped_entries
                        domain_location_list = util.json_loads(line)
                        while append and skipped_entries < append_entries:
                            if len(domain_location_list) <= append_entries - skipped_entries:
                                skipped_entries += len(domain_location_list)
                                domain_location_list[:] = []
                                return next_domains()
                            else:
                                domain_location_list.pop()
                                skipped_entries += 1

                        return True
                    else:
                        domain_location_list = None
                        return False

                def next_domain():
                    with domain_location_list_lock:
                        nonlocal domain_location_list, count_entries
                        if domain_location_list is None:
                            return None
                        if len(domain_location_list) == 0:
                            if not next_domains():
                                return None

                        n_domain = domain_location_list.pop()
                        count_entries += 1
                        if count_entries % 10000 == 0 and not dry_run:
                            logger.info('count {} correct_count {}'.format(count_entries,
                                                                           correct_type_count))
                        while n_domain.ip_for_version(ip_version) not in zmap_results:
                            update_domains(n_domain, util.DomainType.not_responding)
                            if not domain_location_list:
                                if not next_domains():
                                    return None
                            n_domain = domain_location_list.pop()
                            count_entries += 1
                            if count_entries % 10000 == 0 and not dry_run:
                                logger.info('count {} correct_count {}'.format(count_entries,
                                                                               correct_type_count))

                        return n_domain, zmap_results[n_domain.ip_for_version(ip_version)]

                for _ in range(0, MAX_THREADS):
                    thread = threading.Thread(target=domain_check_threading_manage,
                                              args=(next_domain, update_domains,
                                                    update_count_for_type,
                                                    locations,
                                                    zmap_locations,
                                                    distances,
                                                    ripe_create_sema,
                                                    ripe_slow_down_sema,
                                                    ip_version,
                                                    dry_run,
                                                    add_dry_run_matches,
                                                    bill_to_address))

                    threads.append(thread)
                    thread.start()

                for thread in threads:
                    thread.join()

        except KeyboardInterrupt:
            logger.warning('SIGINT recognized stopping Process')
            pass

        if dry_run:
            logger.info('{} matches for {} entries after dry run. {} unreachable addresses. '
                        'Total amount matches: {}. directly verified {}'.format(
                            dry_run_count,
                            (count_entries - count_unreachable - dry_run_verifications),
                            count_unreachable, count_matches, dry_run_verifications))
            util.json_dump(dry_run_matches, output_file)
            output_file.write('\n')
        else:
            dump_domain_list(domains)

        count_alive = 0
        for thread in threads:
            if thread.is_alive():
                count_alive += 1

    logger.info('correct_count {}'.format(correct_type_count))


def domain_check_threading_manage(nextdomain: [[], (util.Domain, [str, float])],
                                  update_domains: [[util.Domain, util.DomainType], ],
                                  update_count_for_type: [[util.LocationCodeType], ],
                                  locations: [str, util.Location],
                                  # chair_server_locks: [str, threading.Lock],
                                  zmap_locations: [str, util.GPSLocation],
                                  distances: [str, [str, float]],
                                  ripe_create_sema: mp.Semaphore,
                                  ripe_slow_down_sema: mp.Semaphore,
                                  ip_version: str,
                                  dry_run: bool,
                                  add_dry_run_matches: [[int], ],
                                  bill_to_address: str=None):
    """The method called to create a thread and manage the domain checks"""
    next_domain_tuple = nextdomain()
    while next_domain_tuple:
        try:
            # logger.debug('next domain')
            check_domain_location_ripe(next_domain_tuple[0], update_domains, update_count_for_type,
                                       locations, zmap_locations, next_domain_tuple[1], distances,
                                       ripe_create_sema, ripe_slow_down_sema, ip_version, dry_run,
                                       add_dry_run_matches, bill_to_address=bill_to_address)
        except Exception:
            logger.exception('Check Domain Error')

        next_domain_tuple = nextdomain()
    logger.debug('Thread finished')


def check_domain_location_ripe(domain: util.Domain,
                               update_domains: [[util.Domain, util.DomainType], ],
                               update_count_for_type: [[util.LocationCodeType], ],
                               locations: [str, util.Location],
                               # chair_server_locks: [str, threading.Lock],
                               zmap_locations: [str, util.GPSLocation],
                               zmap_result: [str, float],
                               distances: [str, [str, float]],
                               ripe_create_sema: mp.Semaphore,
                               ripe_slow_down_sema: mp.Semaphore,
                               ip_version: str,
                               dry_run: bool,
                               add_dry_run_matches: [[int], ],
                               bill_to_address: str=None):
    """checks if ip is at location"""
    matched = False
    results = []

    if zmap_result:
        for zmap_id, zmap_location in zmap_locations.items():
            if zmap_id in zmap_result:
                results.append(util.LocationResult(zmap_id, zmap_result[zmap_id],
                                                   zmap_location))

    eliminate_duplicate_results(results)

    if not results:
        update_domains(domain, util.DomainType.not_responding)
        return
    # else:
    #     results = test_netsec_server(domain['ip'], chair_server_locks)

    if len([res for res in results if res.rtt is not None]) == 0:
        update_domains(domain, util.DomainType.not_responding)
        return

    matches = domain.all_matches

    def get_next_match():
        """

        :rtype: DomainLabelMatch
        """
        nonlocal matches, matched
        logger.debug('{} matches before filter'.format(len(matches)))
        return_val, return_tuple = filter_possible_matches(matches, results, locations, distances)
        logger.debug('{} matches after filter ret val {}'.format(len(matches), return_val))

        if not return_val:
            return None

        if dry_run:
            if return_tuple:
                update_domains(domain, util.DomainType.correct)
                matched = True
                return None
            add_dry_run_matches(matches)
            return None
        else:
            if return_tuple:
                distance, rtt, match = return_tuple
                update_count_for_type(match.code_type)
                match.matching = True
                match.matching_distance = distance
                match.matching_rtt = rtt
                domain.location = locations[str(match.location_id)]
                update_domains(domain, util.DomainType.correct)
                matched = True
                return None
            else:
                ret = None
                if len(matches) > 0:
                    ret = matches[0]
                return ret

    next_match = get_next_match()
    logger.debug('first match')
    no_verification_matches = []

    # TODO refactoring measurements are in dict format
    if not dry_run and next_match is not None:
        measurements = [mes for mes in get_measurements(domain.ip_for_version(ip_version),
                                                        ripe_slow_down_sema)]
        # logger.info('ip {} got measurements {}'.format(domain.ip_for_version(ip_version),
        #                                                 len(measurements)))
    else:
        measurements = []

    while next_match is not None:
        location = locations[str(next_match.location_id)]
        near_nodes = location.nodes

        if not near_nodes:
            matches.remove(next_match)
            no_verification_matches.append(next_match)
            next_match = get_next_match()
            continue

        chk_m, node = check_measurements_for_nodes(measurements,
                                                   location,
                                                   near_nodes,
                                                   results,
                                                   ripe_slow_down_sema)

        def add_new_result(new_result: util.LocationResult):
            remove_obj = None
            for iter_result in results:
                if str(iter_result.location_id) == str(new_result.location_id):
                    if iter_result.rtt <= new_result.rtt:
                        return
                    else:
                        remove_obj = iter_result
                        break
            if remove_obj:
                results.remove(remove_obj)
            results.append(new_result)

        if chk_m is None:
            # only if no old measurement exists
            logger.debug('creating measurement')
            available_nodes = location.available_nodes
            if not available_nodes:
                matches.remove(next_match)
                no_verification_matches.append(next_match)
                next_match = get_next_match()
                continue
            m_results, near_node = create_and_check_measurement(
                (domain.ip_for_version(ip_version), ip_version), location, available_nodes,
                ripe_create_sema, ripe_slow_down_sema, bill_to_address=bill_to_address)
            if m_results is None:
                matches.remove(next_match)
                next_match = get_next_match()
                continue

            node_location_dist = location.gps_distance_equirectangular(
                util.GPSLocation(near_node['geometry']['coordinates'][1],
                                 near_node['geometry']['coordinates'][0]))
            logger.debug('finished measurement')
            try:
                result = next(iter(m_results))
            except StopIteration:
                matches.remove(next_match)
                next_match = get_next_match()
                continue

            chk_res = get_rtt_from_result(result)
            logger.debug('got result {}'.format(chk_res))
            if chk_res is None:
                matches.remove(next_match)
                next_match = get_next_match()
                continue
            elif chk_res == -1:
                update_domains(domain, util.DomainType.not_responding)
                return
            elif chk_res < (MAX_RTT + node_location_dist / 100):
                update_count_for_type(next_match.code_type)
                matched = True
                next_match.matching = True
                next_match.matching_distance = node_location_dist
                next_match.matching_rtt = chk_res
                domain.location = location
                update_domains(domain, util.DomainType.correct)
                break
            else:
                n_res = util.LocationResult(location.id, chk_res, location)
                add_new_result(n_res)
        elif chk_m == -1:
            update_domains(domain, util.DomainType.not_responding)
            return
        else:
            next_match.matching_rtt = chk_m
            node_location_dist = location.gps_distance_equirectangular(
                util.GPSLocation(node['geometry']['coordinates'][1],
                                 node['geometry']['coordinates'][0]))
            next_match.matching_distance = node_location_dist
            if chk_m < (MAX_RTT + node_location_dist / 100):
                update_count_for_type(next_match.code_type)
                matched = True
                next_match.matching = True
                domain.location = location
                update_domains(domain, util.DomainType.correct)
                break
            else:
                n_res = util.LocationResult(location.id, chk_m, location)
                add_new_result(n_res)

        matches.remove(next_match)
        no_verification_matches.append(next_match)
        next_match = get_next_match()
        logger.debug('next match')

    if not matched:
        still_matches = filter_possible_matches(no_verification_matches, results, locations,
                                                distances)[0]
        if still_matches:
            for domain_match in domain.all_matches:
                if domain_match not in no_verification_matches:
                    domain_match.possible = False
            update_domains(domain, util.DomainType.no_verification)
        else:
            for domain_match in domain.all_matches:
                domain_match.possible = False
            update_domains(domain, util.DomainType.no_location)

    return 0


def eliminate_duplicate_results(results: [util.LocationResult]):
    remove_obj = []
    for result in results:
        if result not in remove_obj:
            for inner_result in results:
                if result is not inner_result and inner_result not in remove_obj:
                    if str(result.location_id) == str(inner_result.location_id):
                        if result.rtt < inner_result.rtt:
                            remove_obj.append(inner_result)
                        else:
                            remove_obj.append(result)
                            break

    for obj in remove_obj:
        results.remove(obj)


def filter_possible_matches(matches: [util.DomainLabelMatch], results: [util.LocationResult],
                            locations: [str, util.Location],
                            distances: [str, [str, float]]) -> [util.DomainLabelMatch]:
    """
    Sort the matches after their most probable location
    :returns if there are any matches left
    """
    f_results = [result for result in results if result.rtt is not None]
    f_results.sort(key=lambda res: res.rtt)
    f_results = f_results[:10]
    if len(f_results) > 0:
        near_matches = collections.defaultdict(list)
        for match in matches:
            location_distances = []
            for result in f_results:
                if result.rtt is None:
                    continue
                if result.location_id in distances:
                    distance = distances[result.location_id][str(match.location_id)]
                else:
                    distance = \
                        locations[str(result.location_id)].gps_distance_equirectangular(
                            locations[str(match.location_id)])

                if distance > (result.rtt * 100):
                    break

                # Only verify location if there is also a match
                if distance < 100 and result.rtt < MAX_RTT + distance / 100:
                    return True, (distance, result.rtt, match)

                location_distances.append((result, distance))

            if len(location_distances) != len(f_results):
                continue

            min_res = min(location_distances, key=lambda res: res[1])[0]

            near_matches[str(min_res.location_id)].append(match)

        len_near_matches = 0
        for matches_arr in near_matches.values():
            len_near_matches += len(matches_arr)
        if f_results[0].rtt > 75:
            def match_in_near_matches(m_match):
                for near_match_arr in near_matches.values():
                    if m_match in near_match_arr:
                        return True
                return False

            r_indexes = []
            for i, match in enumerate(matches):
                if not match_in_near_matches(match):
                    r_indexes.append(i)

            for i in r_indexes[::-1]:
                del matches[i]

        else:
            matches.clear()
            finished_location_ids = []
            for result in f_results:
                if str(result.location_id) in near_matches and \
                                str(result.location_id) not in finished_location_ids:
                    finished_location_ids.append(str(result.location_id))
                    matches.extend(near_matches[str(result.location_id)])

    return len(matches) > 0, None


# def test_netsec_server(ip_address: str, chair_server_locks: [str, threading.Lock]) -> \
#         [util.LocationResult]:
#     """Test from the network chairs server the rtts and returns them in a dict"""
#     ret = []
#     server_configs = {
#         'm': {'user': 'root', 'port': 15901, 'server': 'planetlab7.net.in.tum.de'},
#         's': {'user': 'root', 'port': None, 'server': '139.162.29.117'},
#         'd': {'user': 'root', 'port': None, 'server': '45.33.5.55'}
#         }
#     chair_server_locks['m'].acquire()
#     ret.append(util.LocationResult(MUNICH_ID,
#                                    get_min_rtt(
#                                        ssh_ping(server_configs['m'], ip_address)),
#                                    COORDS[MUNICH_ID]['gps_coords']))
#     chair_server_locks['m'].release()
#     chair_server_locks['s'].acquire()
#     ret.append(util.LocationResult(SINGAPORE_ID,
#                                    get_min_rtt(
#                                        ssh_ping(server_configs['s'], ip_address)),
#                                    COORDS[SINGAPORE_ID]['gps_coords']))
#     chair_server_locks['s'].release()
#     chair_server_locks['d'].acquire()
#     ret.append(util.LocationResult(DALLAS_ID,
#                                    get_min_rtt(
#                                        ssh_ping(server_configs['d'], ip_address)),
#                                    COORDS[DALLAS_ID]['gps_coords']))
#     chair_server_locks['d'].release()
#     if ret[0].rtt is None and ret[1].rtt is None and ret[2].rtt is None:
#         return None
#     return ret
#
#
# def ssh_ping(server_conf: [str, [str, object]], ip_address: str) -> str:
#     """Perform a ping from the server with server_conf over ssh"""
#     # build ssh arguments
#     args = ['ssh']
#     if server_conf['port'] is not None:
#         args.append('-p')
#         args.append(str(server_conf['port']))
#     args.append('{0}@{1}'.format(server_conf['user'], server_conf['server']))
#     args.extend(['ping', '-fnc', '4', ip_address])  # '-W 1',
#     try:
#         output = subprocess.check_output(args, timeout=45)
#     except subprocess.CalledProcessError as error:
#         if error.returncode == 1:
#             return None
#         elif error.returncode == 255:
#             time.sleep(3)
#             return ssh_ping(server_conf, ip_address)
#         logger.error(error.output)
#         raise error
#     except subprocess.TimeoutExpired:
#         return None
#     except:
#         raise
#     return str(output)


def get_min_rtt(ping_output: str) -> float:
    """
    parses the min rtt from a ping output
    if the host did not respond returns None
    """
    if ping_output is None:
        return None
    min_rtt_str = ping_output[(ping_output.find('mdev = ') + len('mdev = ')):]
    min_rtt_str = min_rtt_str[:min_rtt_str.find('/')]
    return float(min_rtt_str)


def get_rtt_from_result(measurement_entry: [str, float]) -> float:
    """gets the rtt from measurement_entry"""
    if 'min' in measurement_entry.keys():
        return measurement_entry['min']
    if 'result' in measurement_entry.keys() and len(
            measurement_entry['rtt']) > 0:
        min_rtt = min(measurement_entry['rtt'], key=lambda res: res['rtt'])[
            'rtt']
        return min_rtt
    if 'avg' in measurement_entry.keys():
        return measurement_entry['avg']
    return None


NON_WORKING_PROBES = []
NON_WORKING_PROBES_LOCK = threading.Lock()


def create_and_check_measurement(ip_addr: [str, str],
                                 location: util.Location, nodes: [[str, object]],
                                 ripe_create_sema: mp.Semaphore,
                                 ripe_slow_down_sema: mp.Semaphore,
                                 bill_to_address: str=None) -> \
        ([str, object], [str, object]):
    """creates a measurement for the parameters and checks for the created measurement"""
    near_nodes = [node for node in nodes if node not in NON_WORKING_PROBES]

    def new_near_node():
        """Get a node from the near_nodes and return it"""
        if len(near_nodes) > 0:
            return near_nodes[random.randint(0, len(near_nodes) - 1)]
        else:
            return None

    near_node = new_near_node()
    if near_node is None:
        return None, None

    def new_measurement():
        """Create new measurement"""
        return create_ripe_measurement(ip_addr, location, near_node,
                                       ripe_slow_down_sema, bill_to_address=bill_to_address)

    def sleep_time(amount: int = 15):
        """Sleep for ten seconds"""
        time.sleep(amount)

    with ripe_create_sema:
        measurement_id = new_measurement()
        # sleep for 6 minutes
        sleep_time(amount=360)
        while True:
            if measurement_id is None:
                return None, None
            res = get_ripe_measurement(measurement_id)
            if res is not None:
                if res.status_id == 4:
                    break
                elif res.status_id in [6, 7]:
                    with NON_WORKING_PROBES_LOCK:
                        NON_WORKING_PROBES.append(near_node)

                    near_nodes.remove(near_node)
                    near_node = new_near_node()
                    if near_node is None:
                        return None, None
                    measurement_id = new_measurement()
                    sleep_time(360)
                elif res.status_id in [0, 1, 2]:
                    sleep_time()
            else:
                sleep_time()
    ripe_slow_down_sema.acquire()
    success, m_results = ripe_atlas.AtlasResultsRequest(
        **{'msm_id': measurement_id}).create()
    while not success:
        logger.error('ResultRequest error {}'.format(m_results))
        time.sleep(10 + (random.randrange(0, 500) / 100))
        ripe_slow_down_sema.acquire()
        success, m_results = ripe_atlas.AtlasResultsRequest(
            **{'msm_id': measurement_id}).create()

    return m_results, near_node


USE_WRAPPER = True


def create_ripe_measurement(ip_addr: [str, str], location: util.Location, near_node: [str, object],
                            ripe_slow_down_sema: mp.Semaphore, bill_to_address: str=None) -> int:
    """Creates a new ripe measurement to the first near node and returns the measurement id"""

    if ip_addr[1] == util.IPV4_IDENTIFIER:
        af = 4
    else:
        af = 6

    # TODO RIPE pull request with bill to possibility
    def create_ripe_measurement_wrapper():
        """Creates a new ripe measurement to the first near node and returns the measurement id"""

        ping = ripe_atlas.Ping(af=af, packets=1, target=ip_addr[0],
                               description=ip_addr[0] + ' test for location ' + location.city_name)
        source = ripe_atlas.AtlasSource(value=str(near_node['id']), requested=1,
                                        type='probes')
        if bill_to_address:
            atlas_request = ripe_atlas.AtlasCreateRequest(
                key=API_KEY,
                measurements=[ping],
                sources=[source],
                is_oneoff=True,
                bill_to=bill_to_address
            )
        else:
            atlas_request = ripe_atlas.AtlasCreateRequest(
                key=API_KEY,
                measurements=[ping],
                sources=[source],
                is_oneoff=True
            )
        # ripe_slow_down_sema.acquire()
        (success, response) = atlas_request.create()

        retries = 0
        while not success:
            success, response = atlas_request.create()

            if success:
                break
            time.sleep(10 + (random.randrange(0, 500) / 100))

            retries += 1
            if retries % 5 == 0:
                logger.error('Create error {}'.format(response))

        measurement_ids = response['measurements']
        return measurement_ids[0]

    def create_ripe_measurement_post():
        """Creates a new ripe measurement to the first near node and returns the measurement id"""
        headers = {
            'Content-Type': 'application/json', 'Accept': 'application/json'
            }
        payload = {
            'definitions': [
                {
                    'target': ip_addr[0],
                    'af': af,
                    'packets': 1,
                    'size': 48,
                    'description': ip_addr[0] + ' test for location ' + location[
                        'cityName'],
                    'type': 'ping',
                    'resolve_on_probe': False
                }
            ],
            'probes': [
                {
                    'value': str(near_node['id']),
                    'type': 'probes',
                    'requested': 1
                }
            ],
            'is_oneoff': True,
            'bill_to': bill_to_address
        }

        params = {'key': API_KEY}
        ripe_slow_down_sema.acquire()
        response = requests.post('https://atlas.ripe.net/api/v1/measurement/',
                                 params=params,
                                 headers=headers, json=payload)

        retries = 0
        while response.status_code != 202 and retries < 5:
            if response.status_code == 400:
                logger.error('Create measurement error! {}'.format(response.text))
                return None
            ripe_slow_down_sema.acquire()
            response = requests.post(
                'https://atlas.ripe.net/api/v1/measurement/', params=params,
                headers=headers, json=payload)
            if response.status_code != 202:
                retries += 1

        if response.status_code != 202:
            response.raise_for_status()

        measurement_ids = response.json()['measurements']
        response.close()
        return measurement_ids[0]

    if USE_WRAPPER:
        return create_ripe_measurement_wrapper()
    else:
        return create_ripe_measurement_post()


def get_measurements(ip_addr: str, ripe_slow_down_sema: mp.Semaphore) -> [ripe_atlas.Measurement]:
    """
    Get ripe measurements for ip_addr
    """

    def next_batch(measurement):
        loc_retries = 0
        while True:
            try:
                measurement.next_batch()
            except ripe_atlas.exceptions.APIResponseError:
                # logger.exception('MeasurementRequest APIResponseError next_batch')
                pass
            else:
                break

            time.sleep(5)
            loc_retries += 1

            if loc_retries % 5 == 0:
                logger.error('Ripe next_batch error! {}'.format(ip_addr))

    max_age = int(time.time()) - ALLOWED_MEASUREMENT_AGE
    params = {
        'status': '2,4,5',
        'target_ip': ip_addr,
        'type': 'ping',
        'stop_time__gte': max_age
        }
    ripe_slow_down_sema.acquire()
    retries = 0
    measurements = None

    while True:
        try:
            measurements = ripe_atlas.MeasurementRequest(**params)
        except ripe_atlas.exceptions.APIResponseError:
            logger.exception('MeasurementRequest APIResponseError')
        else:
            break

        time.sleep(5)
        retries += 1

        if retries % 5 == 0:
            logger.error('Ripe MeasurementRequest error! {}'.format(ip_addr))
            time.sleep(30)
    next_batch(measurements)
    if measurements.total_count > 500:
        skip = math.floor(measurements.total_count / 100) - 5

        for _ in range(0, skip):
            next_batch(measurements)

    return measurements


def get_measurements_for_nodes(measurements: [[str, object]], ripe_slow_down_sema: mp.Semaphore,
                               near_nodes: [str, object]):
    """Loads all results for all measurements if they are less than a year ago"""

    for measure in measurements:
        allowed_start_time = int(time.time()) - ALLOWED_MEASUREMENT_AGE

        params = {
            'msm_id': measure['id'],
            'start': allowed_start_time,
            'probe_ids': [node['id'] for node in near_nodes]
            }
        ripe_slow_down_sema.acquire()
        success, result_list = ripe_atlas.AtlasResultsRequest(**params).create()
        retries = 0
        while not success and retries < 5:
            time.sleep(10 + (random.randrange(0, 500) / 100))
            ripe_slow_down_sema.acquire()
            success, result_list = ripe_atlas.AtlasResultsRequest(**params).create()
            if not success:
                retries += 1

        if retries > 4:
            logger.error('AtlasResultsRequest error! {}'.format(result_list))
            continue

        # measure['results'] = result_list
        yield {'msm_id': measure['id'], 'results': result_list}


def check_measurements_for_nodes(measurements: [object], location: util.Location,
                                 nodes: [[str, object]], results: [util.LocationResult],
                                 ripe_slow_down_sema: mp.Semaphore) -> (float, int):
    """
    Check the measurements list for measurements from near_nodes
    :rtype: (float, dict)
    """
    if measurements is None or len(measurements) == 0:
        return None, None

    measurement_results = get_measurements_for_nodes(measurements,
                                                     ripe_slow_down_sema,
                                                     nodes)

    check_n = None
    node_n = None
    date_n = None
    near_node_ids = [node['id'] for node in nodes]
    for m_results in measurement_results:
        for result in m_results['results']:
            oldest_alowed_time = int(time.time()) - ALLOWED_MEASUREMENT_AGE
            if (result['prb_id'] not in near_node_ids or
                    result['timestamp'] < oldest_alowed_time):
                continue

            check_res = get_rtt_from_result(result)
            if check_res is None:
                continue
            elif check_res == -1:
                if check_n is None:
                    check_n = check_res
                if date_n is None or date_n < result['timestamp']:
                    date_n = result['timestamp']
            elif check_n is None or check_res < check_n or check_n == -1:
                node_n = next((near_node for near_node in nodes
                               if near_node['id'] == result['prb_id']))
                check_n = check_res
                results.append(
                    util.LocationResult(location.id, check_res, location=location))

    if check_n is not None:
        if check_n == -1:
            if date_n < int(time.time() - 60*60*24*14):
                return None, None
        return check_n, node_n

    return None, None


def get_ripe_measurement(measurement_id: int):
    """Call the RIPE measurement entry point to get the ripe measurement with measurement_id"""
    retries = 0
    while True:
        try:
            return ripe_atlas.Measurement(id=measurement_id)
        except ripe_atlas.exceptions.APIResponseError:
            time.sleep(5)
            retries += 1
            if retries % 25 == 0:
                logger.exception('Ripe get Measurement (id {}) error!'.format(measurement_id))
            if retries % 5 == 0:
                time.sleep(30)


def json_request_get_wrapper(url: str, ripe_slow_down_sema: mp.Semaphore, params: [str, str]=None,
                             headers: [str, str]=None):
    """Performs a GET request and returns the response dict assuming the answer is json encoded"""
    response = None
    for _ in range(0, 3):
        try:
            if ripe_slow_down_sema is not None:
                ripe_slow_down_sema.acquire()
            response = RIPE_SESSION.get(url, params=params, headers=headers,
                                        timeout=(3.05, 27.05))
        except requests.exceptions.ReadTimeout:
            continue
        else:
            break

    if response is None:
        return None

    if response.status_code >= 500:
        response.close()
        return None

    if response.status_code // 100 != 2:
        response.raise_for_status()
        response.close()
        return None

    json_dct = response.json()
    response.close()

    return json_dct


def get_nearest_ripe_nodes(location: util.Location, max_distance: int, ip_version: str,
                           slow_down_sema: mp.Semaphore=None,
                           thread_sema: threading.Semaphore=None) -> \
        ([[str, object]], [[str, object]]):
    """
    Searches for ripe nodes near the location
    """
    try:
        if max_distance % 50 != 0:
            logger.critical('max_distance must be a multiple of 50')
            return

        distances = [25, 50, 100, 250, 500, 1000]
        if max_distance not in distances:
            distances.append(max_distance)
            distances.sort()

        for distance in distances:
            if distance > max_distance:
                break
            params = {
                'radius': '{},{}:{}'.format(location.lat, location.lon, distance),
                # 'limit': '500'
                }

            # nodes = []
            # available_probes = []
            # next_is_available = True
            # while next_is_available:
            #     params['offset'] = len(nodes)
            #     response_dict = json_request_get_wrapper('https://atlas.ripe.net/api/v1/probe/',
            #                                              slow_down_sema, params=params)
            #     if response_dict is not None and response_dict['meta']['total_count'] > 0:
            #         next_is_available = response_dict['meta']['next'] is not None
            #         nodes.extend(response_dict['objects'])
            #         available_probes = [
            #             node for node in response_dict['objects']
            #             if (node['status_name'] == 'Connected' and
            #                 'system-{}-works'.format(ip_version) in node['tags'] and
            #                 'system-{}-capable'.format(ip_version) in node['tags'])]
            #     else:
            #         break
            # if len(nodes) > 0:
            #     location.nodes = nodes
            #     location.available_nodes = available_probes
            #     return

            slow_down_sema.acquire()
            nodes = ripe_atlas.ProbeRequest(return_objects=True, **params)

            nodes.next_batch()
            if nodes.total_count > 0:
                results = [node for node in nodes]
                available_probes = [node for node in results
                                    if (node.status == 'Connected' and
                                        'system-{}-works'.format(ip_version) in
                                        [tag['slug'] for tag in node.tags] and
                                        'system-{}-capable'.format(ip_version) in
                                        [tag['slug'] for tag in node.tags])]
                if len(available_probes) > 0:
                    location.nodes = results
                    location.available_nodes = available_probes
                    return
        location.nodes = []
        location.available_nodes = []
        return
    finally:
        if thread_sema:
            thread_sema.release()


if __name__ == '__main__':
    main()
