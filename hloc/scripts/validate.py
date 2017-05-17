#!/usr/bin/env python3
"""
Verify obtained location hints with rtt measurements using a predefined treshhold
"""

import argparse
import os
import time
import multiprocessing as mp
import threading
import ripe.atlas.cousteau as ripe_atlas

from hloc import util, constants
from hloc.models import Session, LocationInfo, Location, RipeAtlasProbe

logger = None


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string')
    parser.add_argument('-f', '--file-count', type=int, default=8,
                        help='number of files from preprocessing')
    parser.add_argument('-loc', '--location-file-name', required=True, type=str,
                        help='The path to the location file.'
                             ' The output file from the codes_parser')
    parser.add_argument('-m', '--verifying-method', type=str, default='ripe',
                        choices=['geoip', 'ip2location', 'ripe'],
                        help='Specify the method with wich the locations should be checked')
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
    parser.add_argument('-d', '--dry-run', action='store_true',
                        help='Turns on dry run which returns after the first time computing '
                             'the amount of matches to check')
    parser.add_argument('-o', '--without-new-measurements', action='store_true',
                        help='Evaluate the matches using only data/measurements already available '
                             'locally and remote')
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
                available_probes = []

                for node in nodes:
                    gps_location = Location(lat=node['geometry']['coordinates'][1],
                                            lon=node['geometry']['coordinates'][0])
                    db_session.add(gps_location)

                    probe = RipeAtlasProbe(probe_id=node['id'], location=location)
                    db_session.add(probe)

                    location.nearby_probes.append(probe)
                    if node['status']['name'] == 'Connected' \
                            and 'system-{}-works'.format(ip_version) in \
                                [tag['slug'] for tag in node['tags']] \
                            and 'system-{}-capable'.format(ip_version) in \
                                [tag['slug'] for tag in node['tags']]:
                        available_probes.append(node)

                if len(available_probes) > 5:
                    break
    finally:
        if thread_sema:
            thread_sema.release()


if __name__ == '__main__':
    main()
