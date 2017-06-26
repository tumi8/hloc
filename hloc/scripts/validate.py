#!/usr/bin/env python3
"""
Verify obtained location hints with rtt measurements using a predefined treshhold
"""

import argparse
import time
import multiprocessing as mp
import threading
import collections
import random
import typing

import ripe.atlas.cousteau as ripe_atlas

from hloc import util, constants
from hloc.models import *
from hloc.db_queries import probe_for_id, get_measurements_for_domain
from hloc.exceptions import ProbeError
from hloc.ripe_helper.basics_helper import get_measurement_ids
from hloc.ripe_helper.history_helper import check_measurements_for_nodes

logger = None
MAX_THREADS = 10


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('-v', '--ip-version', type=str, default=constants.IPV4_IDENTIFIER,
                        choices=[constants.IPV4_IDENTIFIER, constants.IPV6_IDENTIFIER],
                        help='specify the ipVersion')
    parser.add_argument('-q', '--ripe-request-limit', type=int,
                        help='How many request should normally be allowed per second '
                             'to the ripe server', default=25)
    parser.add_argument('-b', '--ripe-request-burst-limit', type=int,
                        help='How many request should at maximum be allowed per second'
                             ' to the ripe server', default=40)
    parser.add_argument('-ml', '--measurement-limit', type=int,
                        help='The amount of parallel RIPE Atlas measurements allowed',
                        default=100)
    parser.add_argument('-ak', '--api-key', type=str,
                        help='The RIPE Atlas Api key',
                        default='1dc0b3c2-5e97-4a87-8864-0e5a19374e60')
    parser.add_argument('-bt', '--bill-to', type=str,
                        help='The RIPE Atlas Bill to address')
    parser.add_argument('-o', '--without-new-measurements', action='store_true',
                        help='Evaluate the matches using only data/measurements already available '
                             'locally and remote')
    parser.add_argument('-ma', '--allowed-measurement-age', type=int,
                        help='The allowed measurement age in seconds')
    parser.add_argument('-l', '--log-file', type=str, default='check_locations.log',
                        help='Specify a logging file where the log should be saved')
    parser.add_argument('-ll', '--log-level', type=str, default='INFO',
                        choices=['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the preferred log level')


def __check_args(args):
    """Checks arguments validity"""
    if args.filename_proto.find('{}') < 0:
        raise ValueError(
            'Wrong format for the filename! It must be formatable with the '
            '{}-brackets where the numbers have to be inserted.')


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
    db_session = Session()

    ripe_create_sema = None
    ripe_slow_down_sema = None
    generator_thread = None
    finish_event = None

    if args.verifingMethod == 'ripe':
        ripe_slow_down_sema = mp.BoundedSemaphore(args.ripeRequestBurstLimit)
        ripe_create_sema = mp.Semaphore(args.ripe_measurement_limit)
        global MAX_THREADS

        if args.log_level == 'DEBUG':
            MAX_THREADS = 1
        else:
            MAX_THREADS = int(args.ripe_measurement_limit * 0.2)

        finish_event = threading.Event()
        generator_thread = threading.Thread(target=generate_ripe_request_tokens,
                                            args=(ripe_slow_down_sema, args.ripeRequestLimit,
                                                  finish_event))

        if not args.dry_run:
            locations = db_session.query(LocationInfo)

            if locations and not locations[0].probes:
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

            null_locations = [location for location in locations if not location.available_nodes]

            logger.info('{} locations without nodes'.format(len(null_locations)))

        # logger.debug('Size of locations: {}'.format(pympler.asizeof.asizeof(locations)))
        # logger.debug('Size of zmap results: {}'.format(pympler.asizeof.asizeof(zmap_results)))
        logger.debug('finished ripe')

    processes = []

    # Eventually in future we could adapt it so more processes can be used
    process_count = 1

    if args.log_level == 'DEBUG':
        process_count = 1
    for pid in range(0, process_count):
        process = mp.Process(target=ripe_check_for_list,
                             args=(pid,
                                   ripe_create_sema,
                                   ripe_slow_down_sema,
                                   args.ip_version,
                                   args.bill_to,
                                   args.wo_measurements,
                                   args.allowed_measurement_age,
                                   args.api_key),
                             name='domain_checking_{}'.format(pid))

        processes.append(process)

    for process in processes:
        process.start()

    generator_thread.start()

    alive = len(processes)
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

    if finish_event:
        finish_event.set()

    if generator_thread:
        generator_thread.join()

    logger.debug('{} processes alive'.format(alive))
    end_time = time.time()
    logger.info('running time: {}'.format((end_time - start_time)))
    return 0


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


def get_nearest_ripe_nodes(location: LocationInfo, max_distance: int, ip_version: str,
                           db_session: Session, slow_down_sema: mp.Semaphore=None,
                           thread_sema: threading.Semaphore=None) -> \
        ([[str, object]], [[str, object]]):
    """
    Searches for ripe nodes near the location
    """
    try:
        if max_distance % 50 != 0:
            logger.critical('max_distance must be a multiple of 50')
            return

        distances = [100, 250, 500, 1000]
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

            slow_down_sema.acquire()
            results = ripe_atlas.ProbeRequest(**params)

            results.next_batch()
            if results.total_count > 0:
                nodes = [node for node in results]
                available_probes = 0

                for node in nodes:
                    probe_id = node['id']
                    probe = probe_for_id(probe_id, db_session)

                    if not probe:
                        gps_location = Location(lat=node['geometry']['coordinates'][1],
                                                lon=node['geometry']['coordinates'][0])
                        db_session.add(gps_location)

                        probe = RipeAtlasProbe(probe_id=probe_id, location=location)
                        db_session.add(probe)

                    location.nearby_probes.append(probe)
                    if node['status']['name'] == 'Connected' \
                            and 'system-{}-works'.format(ip_version) in \
                                [tag['slug'] for tag in node['tags']] \
                            and 'system-{}-capable'.format(ip_version) in \
                                [tag['slug'] for tag in node['tags']]:
                        available_probes += 1

                if len(available_probes) > 5:
                    break
    finally:
        if thread_sema:
            thread_sema.release()


def ripe_check_for_list(ripe_create_sema: mp.Semaphore,
                        ripe_slow_down_sema: mp.Semaphore,
                        ip_version: str,
                        bill_to_address: str,
                        wo_measurements: bool,
                        allowed_measurement_age: int,
                        api_key: str):
    """Checks for all domains if the suspected locations are correct"""
    correct_type_count = collections.defaultdict(int)

    # chair_server_locks = {'m': threading.Lock(), 's': threading.Lock(), 'd': threading.Lock()}

    domain_type_count = collections.defaultdict(int)
    db_session = Session()

    def increment_count_for_type(ctype: LocationCodeType):
        correct_type_count[ctype.name] += 1

    def increment_domain_type_count(dtype: DomainType):
        """Append current domain in the domain dict to the dtype"""
        domain_type_count[dtype] += 1

    threads = []
    count_entries = 0

    try:
        def next_domain():
            nonlocal count_entries

            # TODO get lazy next domain
            n_domain = None
            count_entries += 1
            if count_entries % 10000 == 0:
                logger.info('count {} correct_count {}'.format(count_entries,
                                                               correct_type_count))

            return n_domain

        for _ in range(0, MAX_THREADS):
            thread = threading.Thread(target=domain_check_threading_manage,
                                      args=(next_domain,
                                            increment_domain_type_count,
                                            increment_count_for_type,
                                            ripe_create_sema,
                                            ripe_slow_down_sema,
                                            ip_version,
                                            bill_to_address,
                                            wo_measurements,
                                            allowed_measurement_age,
                                            api_key,
                                            db_session))

            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        logger.warning('SIGINT recognized stopping Process')
        pass

    count_alive = 0
    for thread in threads:
        if thread.is_alive():
            count_alive += 1

    logger.info('correct_count {}'.format(correct_type_count))


def domain_check_threading_manage(nextdomain: typing.Callable[[], Domain],
                                  increment_domain_type_count: typing.Callable[[DomainType, ], ],
                                  increment_count_for_type: typing.Callable[[LocationCodeType], ],
                                  ripe_create_sema: mp.Semaphore,
                                  ripe_slow_down_sema: mp.Semaphore,
                                  ip_version: str,
                                  bill_to_address: str,
                                  wo_measurements: bool,
                                  allowed_measurement_age: int,
                                  api_key: str,
                                  db_session: Session):
    """The method called to create a thread and manage the domain checks"""
    next_domain_tuple = nextdomain()
    while next_domain_tuple:
        try:
            # logger.debug('next domain')
            check_domain_location_ripe(next_domain_tuple, increment_domain_type_count,
                                       increment_count_for_type, ripe_create_sema,
                                       ripe_slow_down_sema, ip_version, bill_to_address,
                                       wo_measurements, allowed_measurement_age, api_key, db_session)
        except Exception:
            logger.exception('Check Domain Error')

        next_domain_tuple = nextdomain()
    logger.debug('Thread finished')


def check_domain_location_ripe(domain: Domain,
                               increment_domain_type_count: typing.Callable[[DomainType], ],
                               increment_count_for_type: typing.Callable[[LocationCodeType], ],
                               ripe_create_sema: mp.Semaphore,
                               ripe_slow_down_sema: mp.Semaphore,
                               ip_version: str,
                               bill_to_address: str,
                               wo_measurements: bool,
                               allowed_measurement_age: int,
                               api_key: str,
                               db_session: Session):
    """checks if ip is at location"""
    matched = False
    results = get_measurements_for_domain(domain, ip_version, db_session)

    eliminate_duplicate_results(results)

    if not results and wo_measurements:
        increment_domain_type_count(DomainType.not_responding)
        return

    matches = domain.all_matches

    def get_next_match():
        """

        :rtype: CodeMatch
        """
        nonlocal matches, matched
        logger.debug('{} matches before filter'.format(len(matches)))
        return_val = filter_possible_matches(matches, results)
        logger.debug('{} matches after filter ret val {}'.format(len(matches), return_val))

        if not return_val:
            return None

        if isinstance(return_val, tuple):
            rtt, match = return_val
            increment_count_for_type(match.code_type)
            # match.matching = True
            # match.matching_rtt = rtt

            increment_domain_type_count(DomainType.correct)
            matched = True
            return None
        else:
            ret = None
            if len(matches) > 0:
                ret = matches[0]
            return ret

    logger.debug('first match')
    next_match = get_next_match()

    no_verification_matches = []

    if next_match is not None:
        measurement_ids = get_measurement_ids(str(domain.ip_for_version(ip_version)),
                                              ripe_slow_down_sema, allowed_measurement_age)
    else:
        measurement_ids = []

    while next_match is not None:
        location = next_match.location_info
        near_nodes = location.nearby_probes

        if not near_nodes:
            matches.remove(next_match)
            no_verification_matches.append(next_match)
            next_match = get_next_match()
            continue

        measurement_result = check_measurements_for_nodes(measurement_ids,
                                                          location,
                                                          near_nodes,
                                                          results,
                                                          ripe_slow_down_sema,
                                                          allowed_measurement_age)
        logger.debug('checked for measurement results')

        def add_new_result(new_result: MeasurementResult):
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

        if measurement_result is None:
            if not wo_measurements:
                # only if no old measurement exists
                logger.debug('creating measurement')
                available_nodes = location.available_nodes
                if not available_nodes:
                    matches.remove(next_match)
                    no_verification_matches.append(next_match)
                    next_match = get_next_match()
                    continue

                measurement_result = create_and_check_measurement(
                    str(domain.ip_for_version(ip_version)), ip_version, location, available_nodes,
                    ripe_create_sema, ripe_slow_down_sema, api_key, bill_to_address=bill_to_address)
                if measurement_result is None:
                    matches.remove(next_match)
                    next_match = get_next_match()
                    continue

                node_location_dist = location.gps_distance_haversine(
                    measurement_result.probe_id.location)

                logger.debug('finished measurement')

                if measurement_result.min_rtt is None:
                    increment_domain_type_count(DomainType.not_reachable)
                    return
                elif measurement_result.min_rtt < (constants.DEFAULT_BUFFER_TIME +
                                                   node_location_dist / 100):
                    increment_count_for_type(next_match.code_type)
                    matched = True
                    increment_domain_type_count(DomainType.verified)
                    break
                else:
                    add_new_result(measurement_result)

        elif measurement_result.min_rtt is None:
            increment_domain_type_count(DomainType.not_reachable)
            return
        else:
            node_location_dist = location.gps_distance_haversine(measurement_result.probe.location)

            if measurement_result.min_rtt < (constants.DEFAULT_BUFFER_TIME +
                                             node_location_dist / 100):
                increment_count_for_type(next_match.code_type)
                matched = True
                increment_domain_type_count(DomainType.verified)
                break
            else:
                add_new_result(measurement_result)

        matches.remove(next_match)
        no_verification_matches.append(next_match)
        logger.debug('next match')
        next_match = get_next_match()

    if not matched:
        still_matches = filter_possible_matches(no_verification_matches, results)
        if still_matches:
            increment_domain_type_count(DomainType.verification_not_possible)
        else:
            for domain_match in domain.all_matches:
                domain_match.possible = False
            increment_domain_type_count(DomainType.no_match_possible)

    return 0


def eliminate_duplicate_results(results: [MeasurementResult]):
    remove_obj = []
    for result in results:
        if result not in remove_obj:
            for inner_result in results:
                if result is not inner_result and inner_result not in remove_obj:
                    if result.probe.location.gps_distance_haversine(inner_result.probe.location) \
                            < 100:
                        if result.min_rtt < inner_result.min_rtt:
                            remove_obj.append(inner_result)
                        else:
                            remove_obj.append(result)
                            break

    for obj in remove_obj:
        results.remove(obj)


def filter_possible_matches(matches: [CodeMatch], results: [MeasurementResult]) \
        -> typing.Union[bool, (float, CodeMatch)]:
    """
    Sort the matches after their most probable location
    :returns if there are any matches left
    """
    f_results = results[:]
    f_results.sort(key=lambda res: res.rtt)
    f_results = f_results[:10]

    if not f_results:
        return False
    if len(f_results) > 0:
        near_matches = collections.defaultdict(list)
        for match in matches:
            location_distances = []
            for result in f_results:
                if result.min_rtt is None:
                    continue

                distance = result.probe.location.gps_distance_haversine(match.location_info)

                if distance > result.min_rtt * 100:
                    break

                # Only verify location if there is also a match
                if distance < 100 and \
                        result.min_rtt < constants.DEFAULT_BUFFER_TIME + distance / 100:
                    return result.rtt, match

                location_distances.append((result, distance))

            if len(location_distances) != len(f_results):
                continue

            min_res = min(location_distances, key=lambda res: res[1])[0]

            near_matches[min_res.probe.location].append(match)

        # len_near_matches = 0
        # for matches_arr in near_matches.values():
        #     len_near_matches += len(matches_arr)

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
            handled_locations = set()

            for result in f_results:
                if result.probe.location in near_matches and \
                                result.probe.location not in handled_locations:
                    handled_locations.add(result.probe.location)
                    matches.extend(near_matches[result.probe.location])

    return len(matches) > 0


NON_WORKING_PROBES = []
NON_WORKING_PROBES_LOCK = threading.Lock()


def create_and_check_measurement(ip_addr: str, ip_version: str,
                                 location: LocationInfo, nodes: [Probe],
                                 ripe_create_sema: mp.Semaphore,
                                 ripe_slow_down_sema: mp.Semaphore,
                                 api_key: str,
                                 bill_to_address: str=None) \
        -> typing.Optional[RipeMeasurementResult]:
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
        return None

    with ripe_create_sema:
        while True:
            try:
                params = {
                    RipeAtlasProbe.MeasurementKeys.measurement_name.value:
                        '{} test for location {}'.format(ip_addr, location.name),
                    RipeAtlasProbe.MeasurementKeys.ip_version.value: ip_version,
                    RipeAtlasProbe.MeasurementKeys.api_key.value: api_key,
                    RipeAtlasProbe.MeasurementKeys.ripe_slowdown_sema.value: ripe_slow_down_sema
                }
                if bill_to_address:
                    params[RipeAtlasProbe.MeasurementKeys.bill_to_address.value] = bill_to_address

                measurement_result = near_node.measure_rtt(ip_addr, **params)
                return measurement_result
            except ProbeError:
                with NON_WORKING_PROBES_LOCK:
                    NON_WORKING_PROBES.append(near_node)

                near_nodes.remove(near_node)
                near_node = new_near_node()
                if near_node is None:
                    return None


if __name__ == '__main__':
    main()
