#!/usr/bin/env python3
"""
Verify obtained location hints with rtt measurements using a predefined threshold
"""

import time

import argparse
import collections
import datetime
import enum
import multiprocessing as mp
import operator
import queue
import random
import ripe.atlas.cousteau.exceptions as ripe_exceptions
import threading
import typing
from sqlalchemy.exc import InvalidRequestError

from hloc import util, constants
from hloc.db_utils import get_measurements_for_domain, get_all_domains_splitted_efficient, \
    create_session_for_process, create_engine, get_domains_for_ips
from hloc.exceptions import ProbeError, ServerError
from hloc.models import *
from hloc.models.location import probe_location_info_table
from hloc.ripe_helper.basics_helper import get_measurement_ids
from hloc.ripe_helper.history_helper import check_measurements_for_nodes, load_probes_from_cache

logger = None
engine = None
MAX_THREADS = 10


@enum.unique
class MeasurementStrategy(enum.Enum):
    classic = 'classic'
    anticipated = 'anticipated'
    aggressive = 'aggressive'
    forced = 'forced'

    def aliases(self):
        if self == MeasurementStrategy.classic:
            return ['classic', 'cl']
        elif self == MeasurementStrategy.anticipated:
            return ['anticipated', 'an']
        elif self == MeasurementStrategy.aggressive:
            return ['aggressive', 'ag']
        elif self == MeasurementStrategy.forced:
            return ['forced', 'fd']


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('-p', '--number-processes', type=int, default=4,
                        help='specify the number of processes used')
    parser.add_argument('-s', '--measurement-strategy', type=str,
                        default=MeasurementStrategy.classic.value,
                        choices=(MeasurementStrategy.classic.aliases() +
                                 MeasurementStrategy.anticipated.aliases() +
                                 MeasurementStrategy.aggressive.aliases() +
                                 MeasurementStrategy.forced.aliases()),
                        help='The used measurement strategy. '
                             'See IDP Documentation for further explanation')
    parser.add_argument('-n', '--domain-block-limit', type=int, default=1000,
                        help='The number of domains taken per block to process them')
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
    parser.add_argument('--bill-to', type=str,
                        help='The RIPE Atlas Bill to address')
    parser.add_argument('-o', '--without-new-measurements', action='store_true',
                        help='Evaluate the matches using only data/measurements already available '
                             'locally and remote')
    parser.add_argument('-ma', '--allowed-measurement-age', type=int, default=30*24*60*60,
                        help='The allowed measurement age in seconds (Default 30 days)')
    parser.add_argument('-bt', '--buffer-time', type=float, default=constants.DEFAULT_BUFFER_TIME,
                        help='The assumed amount of time spent in router buffers')
    parser.add_argument('-mp', '--measurement-packets', type=int, default=1,
                        help='Amount of packets per measurement')
    parser.add_argument('-e', '--use-efficient-probes', action='store_true',
                        help='sort probes after second hop latency and use the most efficient ones')
    parser.add_argument('-mt', '--probes-per-measurement', default=1, type=int,
                        help='Maximum amount of probes used per measurement')
    parser.add_argument('-dpf', '--disable-probe-fetching', action='store_true',
                        help='Debug argument to prevent getting ripe probes')
    parser.add_argument('--include-ip-encoded', action='store_true',
                        help='Search also domains of type IP encoded')
    parser.add_argument('--stop-without-old-results', action='store_true',
                        help='Do not measure for domains if there is no existing measurement')
    parser.add_argument('--endless-measurements', action='store_true',
                        help='Should the list of IPs be reapeatedly scanned until the process is '
                             'closed')
    parser.add_argument('--random-domains', action='store_true',
                        help='Select the domains to measure randomly')
    parser.add_argument('--debug', action='store_true', help='Use only one process and one thread')
    parser.add_argument('-l', '--log-file', type=str, default='check_locations.log',
                        help='Specify a logging file where the log should be saved')
    parser.add_argument('-ll', '--log-level', type=str, default='INFO',
                        choices=['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the preferred log level')
    parser.add_argument('-dbn', '--database-name', type=str, default='hloc-measurements')
    parser.add_argument('--ip-filter-file', type=str,
                        help='The file with the IPs which should be validated. '
                             'Only IPs which also have a domain entry in the database are '
                             'considered')


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    global engine
    engine = create_engine(args.database_name)

    global logger
    logger = util.setup_logger(args.log_file, 'check', loglevel=args.log_level,
                               hourly_log_rotation=True)
    logger.debug('starting')

    start_time = time.time()
    Session = create_session_for_process(engine)
    db_session = Session()
    db_session.expire_on_commit = False

    ripe_slow_down_sema = mp.BoundedSemaphore(args.ripe_request_burst_limit)
    ripe_create_sema = mp.Semaphore(args.measurement_limit)
    global MAX_THREADS

    if args.debug:
        MAX_THREADS = 1
    else:
        MAX_THREADS = int(args.measurement_limit / args.number_processes * 1.5)

    finish_event = threading.Event()
    generator_thread = util.start_token_generating_thread(ripe_slow_down_sema,
                                                          args.ripe_request_limit,
                                                          finish_event)

    locations = db_session.query(LocationInfo)

    if not locations.count():
        logger.error('No locations found! Aborting!')
        print('No locations found! Aborting!')
        return 1

    if not args.disable_probe_fetching:
        probe_distances = load_probes_from_cache(db_session).values()

        location_to_probes_dct = assign_location_probes(locations,
                                                        [probe for probe, _ in probe_distances],
                                                        db_session)
        db_session.commit()

        null_locations = [location for location in locations
                          if location.id not in location_to_probes_dct]

        logger.info('{} locations without nodes'.format(len(null_locations)))
    else:
        locations = db_session.query(LocationInfo)
        location_to_probes_dct = {}

        loc_without_probes = 0
        probes = set()

        for location in locations:
            if location.nearby_probes:
                location_to_probes_dct[location.id] = []
                for probe in location.nearby_probes:
                    probes.add(probe)
                    _ = str(probe.location.lat + probe.location.lon) + probe.location.id + \
                        str(probe.second_hop_latency) + probe.probe_id + str(probe.id)
                    location_to_probes_dct[location.id].append((
                        probe,
                        location.gps_distance_haversine(probe.location),
                        probe.location
                    ))
            else:
                loc_without_probes += 1

        logger.debug('expunging probes')

        for probe in probes:
            try:
                db_session.expunge(probe.location)
                db_session.expunge(probe)
            except InvalidRequestError:
                pass

        logger.debug('updating probes')
        update_probes(probes)

        logger.info('{} locations without nodes'.format(loc_without_probes))

    measurement_strategy = MeasurementStrategy(args.measurement_strategy)

    logger.debug('finished ripe')

    processes = []

    process_count = args.number_processes

    if args.debug:
        process_count = 1

    if args.ip_filter_file:
        ip_set = set()
        with open(args.ip_filter_file) as ip_filter_file:
            for line in ip_filter_file:
                ip_set.add(line.strip())

        ips = list(ip_set)
    else:
        ips = None

    db_session.close()

    for pid in range(0, process_count):

        if ips:
            ips_count = len(ips)
            ips_start_index = int(pid * (ips_count / process_count))
            ips_end_index = int((pid + 1) * (ips_count / process_count))

            if pid + 1 == process_count:
                ips_end_index = ips_count

            ips_for_process = ips[ips_start_index:ips_end_index]
        else:
            ips_for_process = None

        process = mp.Process(target=ripe_check_process,
                             args=(pid,
                                   ripe_create_sema,
                                   ripe_slow_down_sema,
                                   args.bill_to,
                                   args.without_new_measurements,
                                   args.allowed_measurement_age,
                                   args.api_key,
                                   args.domain_block_limit,
                                   process_count,
                                   args.include_ip_encoded,
                                   measurement_strategy,
                                   args.probes_per_measurement,
                                   args.buffer_time,
                                   args.measurement_packets,
                                   args.use_efficient_probes,
                                   location_to_probes_dct,
                                   args.stop_without_old_results,
                                   ips_for_process,
                                   args.endless_measurements,
                                   args.random_domains),
                             name='domain_checking_{}'.format(pid))

        processes.append(process)

    for process in processes:
        process.start()

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


def ripe_check_process(pid: int,
                       ripe_create_sema: mp.Semaphore,
                       ripe_slow_down_sema: mp.Semaphore,
                       bill_to_address: str,
                       wo_measurements: bool,
                       allowed_measurement_age: int,
                       api_key: str,
                       domain_block_limit: int,
                       nr_processes: int,
                       include_ip_encoded: bool,
                       measurement_strategy: MeasurementStrategy,
                       number_of_probes_per_measurement: int,
                       buffer_time: float,
                       packets_per_measurement: int,
                       use_efficient_probes: bool,
                       location_to_probes_dct: typing.Dict[
                           str, typing.Tuple[RipeAtlasProbe, float]],
                       stop_without_old_results: bool,
                       ip_list: typing.List[str],
                       endless_measurements: bool,
                       random_domains: bool):
    """Checks for all domains if the suspected locations are correct"""
    correct_type_count = collections.defaultdict(int)

    domain_type_count = collections.defaultdict(int)
    Session = create_session_for_process(engine)
    db_session = Session()
    db_session.expire_on_commit = False

    def increment_count_for_type(ctype: LocationCodeType):
        correct_type_count[ctype.name] += 1

    def increment_domain_type_count(dtype: DomainLocationType):
        """Append current domain in the domain dict to the dtype"""
        domain_type_count[dtype] += 1

    threads = []

    domain_types = [DomainType.valid]
    if include_ip_encoded:
        domain_types.append(DomainType.ip_encoded)

    measurement_results_queue = queue.Queue()
    stop_event = threading.Event()
    save_measurements_thread = threading.Thread(target=measurement_results_saver,
                                                args=(measurement_results_queue, stop_event))
    save_measurements_thread.start()

    try:
        if ip_list:
            domain_generator = get_domains_for_ips(ip_list, db_session, domain_block_limit,
                                                   endless_mode=endless_measurements)
        else:
            domain_generator = get_all_domains_splitted_efficient(pid,
                                                                  domain_block_limit,
                                                                  nr_processes,
                                                                  domain_types,
                                                                  db_session,
                                                                  use_random_order=random_domains,
                                                                  endless_mode=endless_measurements)

        generator_lock = threading.Lock()

        def next_domain_info():
            try:
                with generator_lock:
                    domain = domain_generator.__next__()
                    location_hints = domain.all_label_matches
                    location_hint_tuples = []

                    for location_hint in location_hints:
                        if isinstance(location_hint, CodeMatch):
                            _ = location_hint.location.city_name
                            _ = location_hint.code_type
                            location_hint_tuples.append((location_hint,
                                                         location_hint.location))

                            try:
                                db_session.expunge(location_hint)
                                db_session.expunge(location_hint.location)
                            except InvalidRequestError:
                                pass

                    loc_ip_version = constants.IPV4_IDENTIFIER if domain.ipv4_address else \
                        constants.IPV6_IDENTIFIER

                    measurement_results_query = get_measurements_for_domain(
                        domain,
                        loc_ip_version,
                        allowed_measurement_age,
                        sorted_return=True,
                        db_session=db_session,
                        allow_all_zmap_measurements=True)

                    measurement_result_tuples = []

                    for res in measurement_results_query:
                        _ = res.probe.location
                        measurement_result_tuples.append((res, res.probe.location))
                        try:
                            db_session.expunge(res.probe.location)
                            db_session.expunge(res)
                        except InvalidRequestError:
                            pass

                    db_session.expunge(domain)
                    return domain, location_hint_tuples, measurement_result_tuples
            except StopIteration:
                return None

        for _ in range(0, MAX_THREADS):
            # TODO use ThreadPoolExecutor
            thread = threading.Thread(target=domain_check_threading_manage,
                                      args=(next_domain_info,
                                            increment_domain_type_count,
                                            increment_count_for_type,
                                            ripe_create_sema,
                                            ripe_slow_down_sema,
                                            bill_to_address,
                                            wo_measurements,
                                            allowed_measurement_age,
                                            api_key,
                                            measurement_strategy,
                                            number_of_probes_per_measurement,
                                            buffer_time,
                                            packets_per_measurement,
                                            use_efficient_probes,
                                            location_to_probes_dct,
                                            measurement_results_queue,
                                            stop_without_old_results))

            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    except KeyboardInterrupt:
        logger.warning('SIGINT recognized stopping Process')
        pass
    finally:
        stop_event.set()
        save_measurements_thread.join()

        db_session.close()
        Session.remove()

    count_alive = 0
    for thread in threads:
        if thread.is_alive():
            count_alive += 1

    logger.info('correct_count {}'.format(correct_type_count))


def measurement_results_saver(measurement_results_queue: queue.Queue, stop_event: threading.Event):
    Session = create_session_for_process(engine)
    db_session = Session()

    results = []
    count_results = 0

    while not stop_event.is_set() or not measurement_results_queue.empty():
        try:
            measurement_result = measurement_results_queue.get(timeout=5)
            results.append(measurement_result)
            count_results += 1

            if count_results % 10**5 == 0:
                db_session.bulk_save_objects(results)
                db_session.commit()

                results.clear()
        except queue.Empty:
            pass

    db_session.bulk_save_objects(results)
    db_session.commit()

    db_session.close()
    Session.remove()


def domain_check_threading_manage(next_domain_info: typing.Callable[
                                      [],
                                      typing.Tuple[
                                          Domain,
                                          typing.List[typing.Tuple[LocationHint, Location]],
                                          typing.List[typing.Tuple[MeasurementResult, Location]]
                                      ]],
                                  increment_domain_type_count: typing.Callable[
                                      [DomainLocationType], None],
                                  increment_count_for_type: typing.Callable[
                                      [LocationCodeType], None],
                                  ripe_create_sema: mp.Semaphore,
                                  ripe_slow_down_sema: mp.Semaphore,
                                  bill_to_address: str,
                                  wo_measurements: bool,
                                  allowed_measurement_age: int,
                                  api_key: str,
                                  measurement_strategy: MeasurementStrategy,
                                  number_of_probes_per_measurement: int,
                                  buffer_time: float,
                                  packets_per_measurement: int,
                                  use_efficient_probes: bool,
                                  location_to_probes_dct: typing.Dict[
                                      str, typing.Tuple[RipeAtlasProbe, float, Location]],
                                  measurement_results_queue: queue.Queue,
                                  stop_without_old_results: bool):
    """The method called to create a thread and manage the domain checks"""
    logger.debug('thread started')

    def get_domains() -> typing.Generator[typing.Tuple[Domain, typing.List[LocationHint]],
                                          None, None]:
        while True:
            domain_hints_tuple = next_domain_info()
            if domain_hints_tuple is not None:
                yield domain_hints_tuple
            else:
                break

    for domain, location_hints, measurement_result_tuples in get_domains():
        try:
            logger.debug('next domain %s', domain.name)
            ip_version = constants.IPV4_IDENTIFIER if domain.ipv4_address else \
                constants.IPV6_IDENTIFIER
            check_domain_location_ripe(domain, location_hints, increment_domain_type_count,
                                       increment_count_for_type, ripe_create_sema,
                                       ripe_slow_down_sema, ip_version, bill_to_address,
                                       wo_measurements, allowed_measurement_age, api_key,
                                       measurement_strategy, number_of_probes_per_measurement,
                                       buffer_time, packets_per_measurement, use_efficient_probes,
                                       location_to_probes_dct, measurement_result_tuples,
                                       measurement_results_queue, stop_without_old_results)
        except Exception:
            logger.exception('Check Domain Error %s', domain.name)

    logger.debug('Thread finished')


def check_domain_location_ripe(domain: Domain,
                               location_hints: typing.List[typing.Tuple[LocationHint,
                                                                        LocationInfo]],
                               increment_domain_type_count: typing.Callable[
                                   [DomainLocationType], None],
                               increment_count_for_type: typing.Callable[
                                   [LocationCodeType], None],
                               ripe_create_sema: mp.Semaphore,
                               ripe_slow_down_sema: mp.Semaphore,
                               ip_version: str,
                               bill_to_address: str,
                               wo_measurements: bool,
                               allowed_measurement_age: int,
                               api_key: str,
                               measurement_strategy: MeasurementStrategy,
                               number_of_probes_per_measurement: int,
                               buffer_time: float,
                               packets_per_measurement: int,
                               use_efficient_probes: bool,
                               location_to_probes_dct: typing.Dict[
                                   str, typing.Tuple[RipeAtlasProbe, float, Location]],
                               old_measurement_results: typing.List[typing.Tuple[MeasurementResult,
                                                                                 Location]],
                               measurement_results_queue: queue.Queue,
                               stop_without_old_results: bool):
    """checks if ip is at location"""
    matched = False

    logger.debug('validating domain {}'.format(domain.name))

    allowed_age = allowed_measurement_age
    if old_measurement_results:
        newest_restult_timestamp = old_measurement_results[0][0].timestamp
        time_since_last_result = (datetime.datetime.now() - newest_restult_timestamp).seconds

        if time_since_last_result < allowed_measurement_age:
            allowed_age = time_since_last_result

    logger.debug('number of saved results {}'.format(len(old_measurement_results)))

    results = old_measurement_results
    eliminate_duplicate_results(results)

    if not results and wo_measurements:
        increment_domain_type_count(DomainLocationType.not_responding)
        return

    matches = location_hints

    def add_new_result(new_result: typing.Tuple[MeasurementResult, Location]):
        remove_obj = None
        for iter_result, iter_location in results:
            if str(iter_result.probe_id) == str(new_result[0].probe_id):
                if iter_result.rtt <= new_result[0].rtt:
                    return
                else:
                    remove_obj = iter_result, iter_location
                    break
        if remove_obj:
            results.remove(remove_obj)
        results.append(new_result)

    def get_next_match():
        """

        :rtype: typing.Optional[typing.Tuple[LocationHint, LocationInfo]]
        """
        nonlocal matches, matched
        logger.debug('{} matches before filter'.format(len(matches)))
        return_val = filter_possible_matches(matches, results, buffer_time)
        logger.debug('{} matches after filter ret val {}'.format(len(matches), return_val))

        if not return_val:
            return None

        if isinstance(return_val, tuple):
            rtt, match_tuple = return_val
            increment_count_for_type(match_tuple[0].code_type)

            increment_domain_type_count(DomainLocationType.verified)
            matched = True
            return None
        else:
            ret = None
            if matches:
                ret = matches[0]
            return ret

    next_match_tup = get_next_match()
    logger.debug('first match (is not None: {})'.format(next_match_tup is not None))

    no_verification_matches = []

    if next_match_tup is not None:
        measurement_ids = get_measurement_ids(str(domain.ip_for_version(ip_version)),
                                              ripe_slow_down_sema, allowed_age)
        logger.debug('number of ripe measurements {}'.format(len(measurement_ids)))
    else:
        measurement_ids = []

    if stop_without_old_results and \
            (not measurement_ids and not old_measurement_results):
        increment_domain_type_count(DomainLocationType.not_reachable)
        logger.debug('not reachable')
        return

    while next_match_tup is not None:
        try:
            location = next_match_tup[1]
            next_match = next_match_tup[0]
            near_node_distances = location_to_probes_dct.get(location.id)

            if not near_node_distances:
                logger.debug('could not find nodes near location id "{}"'.format(location.id))
                no_verification_matches.append((next_match, location))
                continue

            logger.debug('match_id {} location_id {} #near_nodes {}'.format(next_match.id,
                                                                            location.id,
                                                                            len(near_node_distances)
                                                                            ))

            probes = [probe for probe, _, _ in near_node_distances]
            measurement_results = check_measurements_for_nodes(measurement_ids,
                                                               probes,
                                                               ripe_slow_down_sema,
                                                               allowed_age)

            measurement_result = None
            make_measurement = True
            if measurement_results:
                make_measurement = False

                for res in measurement_results:
                    if res.min_rtt:
                        measurement_results_queue.put(res)

                measurement_result = measurement_results[0]
                used_probe, node_location_dist, used_probe_loc = \
                    [(probe, dst, probe_loc) for probe, dst, probe_loc in near_node_distances
                     if probe.id == measurement_result.probe_id][0]

                if measurement_result.min_rtt:
                    add_new_result((measurement_result, used_probe_loc))

                logger.debug('checked for measurement results')

                if not wo_measurements:
                    make_measurement = make_measurement or (measurement_result.min_rtt is None and
                                                            measurement_strategy in [
                                                                MeasurementStrategy.anticipated,
                                                                MeasurementStrategy.aggressive])
                    if not make_measurement:
                        make_measurement = measurement_result.min_rtt >= (
                            buffer_time + node_location_dist / 100)

            if make_measurement:
                if not wo_measurements:
                    # only if no old measurement exists
                    logger.debug('creating measurement')
                    available_nodes = __get_available_probes([ip_version], probes)

                    if not available_nodes:
                        logger.debug(
                            'could not find nodes near location id "{}"'.format(location.id))
                        no_verification_matches.append((next_match, location))
                        continue

                    measurement_result = create_and_check_measurement(
                        str(domain.ip_for_version(ip_version)), ip_version, location,
                        available_nodes[:3*number_of_probes_per_measurement],
                        ripe_create_sema,
                        ripe_slow_down_sema,
                        api_key,
                        bill_to_address=bill_to_address,
                        number_of_probes=number_of_probes_per_measurement,
                        number_of_packets=packets_per_measurement,
                        use_efficient_probes=use_efficient_probes
                    )

                    if not measurement_result:
                        logger.debug('creating and gettign measurement result failed')
                        continue

                    if not measurement_result.min_rtt:
                        increment_domain_type_count(DomainLocationType.not_reachable)
                        logger.debug('not reachable')
                        return

                    measurement_results_queue.put(measurement_result)

                    used_probe, node_location_dist, used_probe_loc = \
                        [(probe, dst, probe_loc) for probe, dst, probe_loc in near_node_distances
                         if probe.id == measurement_result.probe_id][0]

                    logger.debug('finished measurement')

                    if measurement_result.min_rtt < (buffer_time + node_location_dist / 100):
                        increment_count_for_type(next_match.code_type)
                        matched = True
                        increment_domain_type_count(DomainLocationType.verified)
                        logger.debug('success')
                        break
                    else:
                        add_new_result((measurement_result, used_probe_loc))
                else:
                    logger.debug('skipping active measurement as it is deactivated')

            elif not measurement_result or measurement_result.min_rtt is None:
                increment_domain_type_count(DomainLocationType.not_reachable)
                logger.debug('not reachable')
                return
            else:
                used_probe, node_location_dist, used_probe_loc = \
                    [(probe, dst, probe_loc) for probe, dst, probe_loc in near_node_distances
                     if probe.id == measurement_result.probe_id][0]

                if measurement_result.min_rtt < (buffer_time + node_location_dist / 100):
                    increment_count_for_type(next_match.code_type)
                    matched = True
                    increment_domain_type_count(DomainLocationType.verified)
                    logger.debug('success')
                    break
                else:
                    logger.debug('adding new non verification result')
                    add_new_result(measurement_result)

            no_verification_matches.append((next_match, location))
            logger.debug('next match')
        finally:
            if not matched:
                matches.remove(next_match_tup)
                next_match_tup = get_next_match()

    if not matched:
        still_matches = filter_possible_matches(no_verification_matches, results, buffer_time)
        if still_matches:
            increment_domain_type_count(DomainLocationType.verification_not_possible)
        else:
            for domain_match in domain.all_label_matches:
                domain_match.possible = False
            increment_domain_type_count(DomainLocationType.no_match_possible)

    return 0


def __get_available_probes(ip_versions: [str], probes: [RipeAtlasProbe]):
    ip_versions_needed = []
    if constants.IPV4_IDENTIFIER in ip_versions and constants.IPV6_IDENTIFIER in ip_versions:
        ip_versions_needed.append(AvailableType.both_available)
    elif constants.IPV4_IDENTIFIER in ip_versions:
        ip_versions_needed.append(AvailableType.ipv4_available)
    elif constants.IPV6_IDENTIFIER in ip_versions:
        ip_versions_needed.append(AvailableType.ipv6_available)
    else:
        raise ValueError('no valid ip version in ip versions list')

    available_probes = []

    for probe in probes:
        try:
            if probe.available() in ip_versions_needed:
                available_probes.append(probe)
        except ProbeError:
            logger.exception('Probe Error on probe with id %s and ripe_atlas id %s', probe.id,
                             probe.probe_id)
            NON_WORKING_PROBE_IDS.add(probe.id)

    return available_probes


def eliminate_duplicate_results(results: [typing.Tuple[MeasurementResult, Location]]):
    remove_obj = set()
    for result, location in results:
        if (result, location) not in remove_obj:
            for inner_result, inner_location in results:
                if result is not inner_result and inner_result not in remove_obj:
                    if location.gps_distance_haversine(inner_location) < 100:
                        if result.min_rtt < inner_result.min_rtt:
                            remove_obj.add((inner_result, inner_location))
                        else:
                            remove_obj.add((result, location))
                            break

    for obj in remove_obj:
        results.remove(obj)


def filter_possible_matches(matches: [typing.Tuple[LocationHint, LocationInfo]],
                            results: [typing.Tuple[MeasurementResult, Location]],
                            buffer_time: float) \
        -> typing.Union[bool, typing.Tuple[float, typing.Tuple[LocationHint, LocationInfo]]]:
    """
    Sort the matches after their most probable location
    :returns if there are any matches left
    """

    if not results:
        return True if matches else False

    f_results = results[:]
    f_results.sort(key=lambda res: res[0].rtt)
    f_results = f_results[:10]

    near_matches = collections.defaultdict(list)
    for match, location_info in matches:
        location_distances = []
        for result, loc in f_results:
            if result.min_rtt is None:
                continue

            distance = loc.gps_distance_haversine(location_info)

            if distance > result.min_rtt * 100:
                break

            # Only verify location if there is also a match
            if distance < 100 and \
                    result.min_rtt < buffer_time + distance / 100:
                return result.rtt, (match, location_info)

            location_distances.append(((result, loc), distance))

        if len(location_distances) != len(f_results):
            continue

        min_res = min(location_distances, key=lambda res: res[0][0].rtt)[0]

        near_matches[min_res[1]].append((match, location_info))

    if not f_results[0][0].rtt or f_results[0][0].rtt > 75:
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

        for result, loc in f_results:
            if loc in near_matches and loc not in handled_locations:
                handled_locations.add(loc)
                matches.extend(near_matches[loc])

    return True if matches else False


NON_WORKING_PROBE_IDS = set()


def create_and_check_measurement(ip_addr: str, ip_version: str,
                                 location: LocationInfo, nodes: [Probe],
                                 ripe_create_sema: mp.Semaphore,
                                 ripe_slow_down_sema: mp.Semaphore,
                                 api_key: str,
                                 bill_to_address: str=None,
                                 number_of_probes: int=1,
                                 number_of_packets: int=1,
                                 use_efficient_probes: bool=False) \
        -> typing.Optional[RipeMeasurementResult]:
    """creates a measurement for the parameters and checks for the created measurement"""
    if number_of_probes <= 0:
        raise ValueError('number_of_probes must be larger than 0')

    near_nodes_all = [node for node in nodes if node.id not in NON_WORKING_PROBE_IDS]

    logger.debug('%s near nodes not blacklisted', len(near_nodes_all))

    near_nodes = near_nodes_all[:]
    if use_efficient_probes:
        near_nodes.sort(key=lambda x: x.second_hop_latency if x.second_hop_latency else 10000)
        near_nodes = near_nodes[:number_of_probes * 2]

    while len(near_nodes) > number_of_probes:
        del near_nodes[random.randint(0, len(near_nodes) - 1)]

    logger.debug('%s nodes for selection of %s we would like to use', len(near_nodes),
                 number_of_probes)

    if not near_nodes:
        return None

    with ripe_create_sema:
        while True:
            try:
                params = {
                    RipeAtlasProbe.MeasurementKeys.measurement_name.value:
                        'HLOC Geolocation Measurement for location {}'.format(location.city_name),
                    RipeAtlasProbe.MeasurementKeys.ip_version.value: ip_version,
                    RipeAtlasProbe.MeasurementKeys.api_key.value: api_key,
                    RipeAtlasProbe.MeasurementKeys.ripe_slowdown_sema.value: ripe_slow_down_sema,
                    RipeAtlasProbe.MeasurementKeys.num_packets.value: number_of_packets,
                    RipeAtlasProbe.MeasurementKeys.additional_probes.value: near_nodes[1:],
                    RipeAtlasProbe.MeasurementKeys.tags.value: [constants.HLOC_RIPE_TAG]
                }
                if bill_to_address:
                    params[RipeAtlasProbe.MeasurementKeys.bill_to_address.value] = bill_to_address

                measurement_result = near_nodes[0].measure_rtt(ip_addr, **params)

                return measurement_result
            except ProbeError:
                logger.warning('Probe error for probe id %s', near_nodes[0].id, exc_info=True)

                for node in near_nodes:
                    NON_WORKING_PROBE_IDS.add(node.id)
                    near_nodes_all.remove(node)

                near_nodes = near_nodes_all[:]
                while len(near_nodes) > number_of_probes:
                    del near_nodes[random.randint(0, len(near_nodes) - 1)]

                if not near_nodes:
                    return None
            except ServerError:
                # RA server returned status >= 500
                # solution is trying to sleep for 5 - 10 minutes and then try again
                logger.exception('RA has server issues')
                print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'RA has Server issues')
                time.sleep(300 + random.randrange(0, 300))


def update_probes(probes: [RipeAtlasProbe]):
    def _update(probe_queue_int: queue.Queue):
        try:
            while True:
                probe_t = probe_queue_int.get(timeout=1)
                retries = 0
                while True:
                    try:
                        probe_t.update()
                    except ripe_exceptions.APIResponseError:
                        retries += 1

                        if retries % 5 == 0:
                            logger.exception('ripe ApiResponseError mod 5:')
                    else:
                        break
        except queue.Empty:
            pass

    probe_queue = queue.Queue()
    for probe in probes:
        probe_queue.put(probe)

    threads = []
    for i in range(10):
        thread = threading.Thread(target=_update, args=(probe_queue,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    logger.info('updated probes')


def assign_location_probes(locations: [LocationInfo], probes: [RipeAtlasProbe],
                           db_session) -> typing.Dict[str,
                                                      typing.Tuple[RipeAtlasProbe,
                                                                   float,
                                                                   Location]]:
    near_probes_assignments = []
    location_to_probes_dct = {}

    for location in locations:
        near_probes = []
        for probe in probes:
            dist = probe.location.gps_distance_haversine(location)
            if dist < 1000:
                _ = str(probe.location.lat) + str(probe.location.lon) + probe.location.id + \
                    str(probe.second_hop_latency)
                near_probes.append((probe, dist, probe.location))

        near_probes.sort(key=operator.itemgetter(1))
        near_probes = near_probes[:200]
        location_to_probes_dct[location.id] = near_probes
        near_probes_assignments.extend([{'probe_id': probe[0].id,
                                         'location_info_id': location.id}
                                        for probe in near_probes])

    for probe in probes:
        try:
            db_session.expunge(probe.location)
            db_session.expunge(probe)
        except InvalidRequestError:
            pass

    db_session.execute(probe_location_info_table.delete())
    insert_expr = probe_location_info_table.insert().values(near_probes_assignments)
    db_session.execute(insert_expr)

    return location_to_probes_dct


if __name__ == '__main__':
    main()
