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
import enum
import datetime
import operator

import ripe.atlas.cousteau as ripe_atlas
import ripe.atlas.cousteau.exceptions as ripe_exceptions

from hloc import util, constants
from hloc.models import *
from hloc.db_utils import get_measurements_for_domain, create_session_for_process, \
    get_all_domain_ids_splitted, domain_by_id, probe_for_id, location_for_coordinates
from hloc.exceptions import ProbeError
from hloc.ripe_helper.basics_helper import get_measurement_ids
from hloc.ripe_helper.history_helper import check_measurements_for_nodes

logger = None
MAX_THREADS = 10


@enum.unique
class MeasurementStrategy(enum.Enum):
    classic = 'classic'
    anticipated = 'anticipated'
    aggressive = 'aggressive'

    def aliases(self):
        if self == MeasurementStrategy.classic:
            return ['classic', 'cl']
        elif self == MeasurementStrategy.anticipated:
            return ['anticipated', 'an']
        elif self == MeasurementStrategy.aggressive:
            return ['aggressive', 'ag']


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('-p', '--number-processes', type=int, default=4,
                        help='specify the number of processes used')
    parser.add_argument('-v', '--ip-version', type=str, default=constants.IPV4_IDENTIFIER,
                        choices=[constants.IPV4_IDENTIFIER, constants.IPV6_IDENTIFIER],
                        help='specify the ipVersion')
    parser.add_argument('-s', '--measurement-strategy', type=str,
                        default=MeasurementStrategy.classic.value,
                        choices=(MeasurementStrategy.classic.aliases() +
                                 MeasurementStrategy.anticipated.aliases() +
                                 MeasurementStrategy.aggressive.aliases()),
                        help='The used measurement strategy. '
                             'See IDP Documentation for further explanation')
    parser.add_argument('--number-of-probes-per-measurement', type=int, default=1,
                        help='The number of probes used per measurement')
    parser.add_argument('-n', '--domain-block-limit', type=int, default=10,
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
    parser.add_argument('-bt', '--bill-to', type=str,
                        help='The RIPE Atlas Bill to address')
    parser.add_argument('-o', '--without-new-measurements', action='store_true',
                        help='Evaluate the matches using only data/measurements already available '
                             'locally and remote')
    parser.add_argument('-ma', '--allowed-measurement-age', type=int,
                        help='The allowed measurement age in seconds')
    parser.add_argument('-dpf', '--disable-probe-fetching', action='store_true',
                        help='Debug argument to prevent getting ripe probes')
    parser.add_argument('--include-ip-encoded', action='store_true',
                        help='Search also domains of type IP encoded')
    parser.add_argument('-l', '--log-file', type=str, default='check_locations.log',
                        help='Specify a logging file where the log should be saved')
    parser.add_argument('-ll', '--log-level', type=str, default='INFO',
                        choices=['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the preferred log level')


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    global logger
    logger = util.setup_logger(args.log_file, 'check', loglevel=args.log_level)
    logger.debug('starting')

    start_time = time.time()
    Session = create_session_for_process()
    db_session = Session()

    ripe_slow_down_sema = mp.BoundedSemaphore(args.ripe_request_burst_limit)
    ripe_create_sema = mp.Semaphore(args.measurement_limit)
    global MAX_THREADS

    if args.log_level == 'DEBUG':
        MAX_THREADS = 5
    else:
        MAX_THREADS = int(args.ripe_measurement_limit * 0.2)

    finish_event = threading.Event()
    generator_thread = threading.Thread(target=generate_ripe_request_tokens,
                                        args=(ripe_slow_down_sema, args.ripe_request_limit,
                                              finish_event))

    if not args.disable_probe_fetching:
        db_session.query(RipeAtlasProbe).delete()
        locations = db_session.query(LocationInfo)

        probes = get_ripe_probes(db_session)
        assign_location_probes(locations, probes)
        db_session.commit()

        null_locations = [location for location in locations if not location.available_nodes]

        logger.info('{} locations without nodes'.format(len(null_locations)))

    measurement_strategy = MeasurementStrategy(args.measurement_strategy)

    logger.debug('finished ripe')

    processes = []

    process_count = args.number_processes

    if args.log_level == 'DEBUG':
        process_count = 1

    for pid in range(0, process_count):
        process = mp.Process(target=ripe_check_process,
                             args=(pid,
                                   ripe_create_sema,
                                   ripe_slow_down_sema,
                                   args.ip_version,
                                   args.bill_to,
                                   args.without_new_measurements,
                                   args.allowed_measurement_age,
                                   args.api_key,
                                   args.domain_block_limit,
                                   process_count,
                                   args.include_ip_encoded,
                                   measurement_strategy,
                                   args.number_of_probes_per_measurement),
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


def ripe_check_process(pid: int,
                       ripe_create_sema: mp.Semaphore,
                       ripe_slow_down_sema: mp.Semaphore,
                       ip_version: str,
                       bill_to_address: str,
                       wo_measurements: bool,
                       allowed_measurement_age: int,
                       api_key: str,
                       domain_block_limit: int,
                       nr_processes: int,
                       include_ip_encoded: bool,
                       measurement_strategy: MeasurementStrategy,
                       number_of_probes_per_measurement: int):
    """Checks for all domains if the suspected locations are correct"""
    correct_type_count = collections.defaultdict(int)

    domain_type_count = collections.defaultdict(int)
    Session = create_session_for_process()
    db_session = Session()

    def increment_count_for_type(ctype: LocationCodeType):
        correct_type_count[ctype.name] += 1

    def increment_domain_type_count(dtype: DomainLocationType):
        """Append current domain in the domain dict to the dtype"""
        domain_type_count[dtype] += 1

    threads = []
    count_entries = 0

    domain_types = [DomainType.valid]
    if include_ip_encoded:
        domain_types.append(DomainType.ip_encoded)

    try:
        domain_id_generator = get_all_domain_ids_splitted(pid, domain_block_limit, nr_processes,
                                                          domain_types,
                                                          db_session)

        def next_domain_id():
            try:
                return domain_id_generator.__next__()
            except StopIteration:
                return None

        for _ in range(0, MAX_THREADS):
            thread = threading.Thread(target=domain_check_threading_manage,
                                      args=(next_domain_id,
                                            increment_domain_type_count,
                                            increment_count_for_type,
                                            ripe_create_sema,
                                            ripe_slow_down_sema,
                                            ip_version,
                                            bill_to_address,
                                            wo_measurements,
                                            allowed_measurement_age,
                                            api_key,
                                            measurement_strategy,
                                            number_of_probes_per_measurement,
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


def domain_check_threading_manage(next_domain_id: typing.Callable[[], int],
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
                                  Session: typing.Callable[[], Session]):
    """The method called to create a thread and manage the domain checks"""
    db_session = Session()

    def get_domains() -> typing.Generator[Domain, None, None]:
        while True:
            domain_id = next_domain_id()
            if domain_id is not None:
                t_domain = domain_by_id(domain_id, db_session)
                yield t_domain
            else:
                break

    for domain in get_domains():
        try:
            # logger.debug('next domain')
            check_domain_location_ripe(domain, increment_domain_type_count,
                                       increment_count_for_type, ripe_create_sema,
                                       ripe_slow_down_sema, ip_version, bill_to_address,
                                       wo_measurements, allowed_measurement_age, api_key,
                                       measurement_strategy, number_of_probes_per_measurement,
                                       db_session)
            db_session.commit()
        except Exception:
            logger.exception('Check Domain Error')

    logger.debug('Thread finished')


def check_domain_location_ripe(domain: Domain,
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
                               db_session: Session):
    """checks if ip is at location"""
    matched = False
    results = get_measurements_for_domain(domain, ip_version, allowed_measurement_age,
                                          sorted_return=True, db_session=db_session)

    allowed_age = allowed_measurement_age
    if results:
        newest_restult_timestamp = results[0].timestamp
        time_since_last_result = (datetime.datetime.now() - newest_restult_timestamp).seconds

        if time_since_last_result < allowed_measurement_age:
            allowed_age = time_since_last_result

    eliminate_duplicate_results(results)

    if not results and wo_measurements:
        increment_domain_type_count(DomainLocationType.not_responding)
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

            increment_domain_type_count(DomainLocationType.correct)
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
                                              ripe_slow_down_sema, allowed_age)
    else:
        measurement_ids = []

    while next_match is not None:
        try:
            location = next_match.location_info
            near_nodes = location.nearby_probes

            if not near_nodes:
                no_verification_matches.append(next_match)
                continue

            measurement_results = check_measurements_for_nodes(measurement_ids,
                                                               near_nodes,
                                                               ripe_slow_down_sema,
                                                               allowed_age)
            db_session.add_all(measurement_results)

            measurement_result = measurement_results[0]
            results.append(measurement_result)

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

            make_measurement = measurement_result is None
            if not wo_measurements:
                make_measurement = make_measurement or (measurement_result.min_rtt is None and
                                                        measurement_strategy in [
                                                            MeasurementStrategy.anticipated,
                                                            MeasurementStrategy.aggressive])
                if not make_measurement:
                    node_location_dist = location.gps_distance_haversine(
                        measurement_result.probe.location)

                    make_measurement = measurement_result.min_rtt >= (
                        constants.DEFAULT_BUFFER_TIME + node_location_dist / 100)

            if make_measurement:
                if not wo_measurements:
                    # only if no old measurement exists
                    logger.debug('creating measurement')
                    available_nodes = location.available_probes([ip_version])

                    if not available_nodes:
                        no_verification_matches.append(next_match)
                        continue

                    measurement_results = create_and_check_measurement(
                        str(domain.ip_for_version(ip_version)), ip_version, location,
                        available_nodes, ripe_create_sema, ripe_slow_down_sema, api_key,
                        bill_to_address=bill_to_address,
                        number_of_probes=number_of_probes_per_measurement)

                    if not measurement_results:
                        continue

                    measurement_result = min(measurement_results, key=lambda result: result.min_rtt)

                    db_session.add_all(measurement_results)

                    node_location_dist = location.gps_distance_haversine(
                        measurement_result.probe_id.location)

                    logger.debug('finished measurement')

                    if measurement_result.min_rtt is None:
                        increment_domain_type_count(DomainLocationType.not_reachable)
                        return
                    elif measurement_result.min_rtt < (constants.DEFAULT_BUFFER_TIME +
                                                       node_location_dist / 100):
                        increment_count_for_type(next_match.code_type)
                        matched = True
                        increment_domain_type_count(DomainLocationType.verified)
                        break
                    else:
                        add_new_result(measurement_result)

            elif measurement_result.min_rtt is None:
                increment_domain_type_count(DomainLocationType.not_reachable)
                return
            else:
                node_location_dist = location.gps_distance_haversine(
                    measurement_result.probe.location)

                if measurement_result.min_rtt < (constants.DEFAULT_BUFFER_TIME +
                                                 node_location_dist / 100):
                    increment_count_for_type(next_match.code_type)
                    matched = True
                    increment_domain_type_count(DomainLocationType.verified)
                    break
                else:
                    add_new_result(measurement_result)

            no_verification_matches.append(next_match)
            logger.debug('next match')
        finally:
            if not matched:
                matches.remove(next_match)
                next_match = get_next_match()

            db_session.commit()

    if not matched:
        still_matches = filter_possible_matches(no_verification_matches, results)
        if still_matches:
            increment_domain_type_count(DomainLocationType.verification_not_possible)
        else:
            for domain_match in domain.all_matches:
                domain_match.possible = False
            increment_domain_type_count(DomainLocationType.no_match_possible)

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
        -> typing.Union[bool, typing.Tuple[float, CodeMatch]]:
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


NON_WORKING_PROBES = set()


def create_and_check_measurement(ip_addr: str, ip_version: str,
                                 location: LocationInfo, nodes: [Probe],
                                 ripe_create_sema: mp.Semaphore,
                                 ripe_slow_down_sema: mp.Semaphore,
                                 api_key: str,
                                 bill_to_address: str=None,
                                 number_of_probes: int=1,
                                 number_of_packets: int=1) \
        -> typing.Optional[typing.List[RipeMeasurementResult]]:
    """creates a measurement for the parameters and checks for the created measurement"""
    near_nodes_all = [node for node in nodes if node not in NON_WORKING_PROBES]

    near_nodes = near_nodes_all[:]

    if number_of_probes <= 0:
        raise ValueError('number_of_probes must be larger than 0')

    while len(near_nodes) > number_of_probes:
        del near_nodes[random.randint(0, len(near_nodes) - 1)]

    if not near_nodes:
        return None

    with ripe_create_sema:
        while True:
            try:
                params = {
                    RipeAtlasProbe.MeasurementKeys.measurement_name.value:
                        '{} test for location {}'.format(ip_addr, location.name),
                    RipeAtlasProbe.MeasurementKeys.ip_version.value: ip_version,
                    RipeAtlasProbe.MeasurementKeys.api_key.value: api_key,
                    RipeAtlasProbe.MeasurementKeys.ripe_slowdown_sema.value: ripe_slow_down_sema,
                    RipeAtlasProbe.MeasurementKeys.num_packets.value: number_of_packets
                }
                if bill_to_address:
                    params[RipeAtlasProbe.MeasurementKeys.bill_to_address.value] = bill_to_address

                # TODO change code for multiple nodes emasurements
                measurement_results = [near_nodes[0].measure_rtt(ip_addr, **params)]

                return measurement_results
            except ProbeError:
                NON_WORKING_PROBES.add(near_nodes[0])
                for node in near_nodes:
                    near_nodes_all.remove(node)

                while len(near_nodes) > number_of_probes:
                    del near_nodes[random.randint(0, len(near_nodes) - 1)]

                if not near_nodes:
                    return None


def get_ripe_probes(db_session: Session) -> typing.List[RipeAtlasProbe]:
    probes = []

    logger.info('Getting the nodes from RIPE Atlas')

    ripe_probes = ripe_atlas.ProbeRequest(return_objects=True)

    while True:
        try:
            for probe in ripe_probes:
                if not probe.geometry:
                    continue
                probes.append(parse_probe(probe, db_session))
            break
        except ripe_exceptions.APIResponseError as e:
            logger.warning(str(e))

    db_session.commit()

    return probes


def parse_probe(probe: ripe_atlas.Probe, db_session: Session) -> RipeAtlasProbe:
    probe_db_obj = probe_for_id(probe.id, db_session)

    if probe_db_obj:
        if probe_db_obj.update():
            return probe_db_obj

    location = location_for_coordinates(probe.geometry['coordinates'][1],
                                        probe.geometry['coordinates'][0],
                                        db_session)

    probe_db_obj = RipeAtlasProbe(probe_id=probe.id, location=location)
    db_session.add(probe_db_obj)
    return probe_db_obj


def assign_location_probes(locations: [LocationInfo], probes: [RipeAtlasProbe]):
    for location in locations:
        near_probes = []
        for probe in probes:
            dist = probe.location.gps_distance_haversine(location)
            if dist < 1000000:
                near_probes.append((probe, dist))

        near_probes.sort(key=operator.itemgetter(1))

        location.probes.clear()
        location.probes.extend([probe[0] for probe in near_probes])


if __name__ == '__main__':
    main()
