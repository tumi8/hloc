#!/usr/bin/env python3
"""
This module evaluate probeAPI against Ripe Atlas coverage
"""
import argparse
import requests
import collections
import ripe.atlas.cousteau as ripe_atlas
import threading
import math
import time

from . import util

logger = None


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Adds the parameters to the argument parser"""
    parser.add_argument('location_file_name', type=str,
                        help='The path to the location file.'
                             ' The output file from the codes_parser')
    parser.add_argument('-q', '--ripe-request-limit', type=int,
                        dest='ripeRequestLimit',
                        help='How many request should normally be allowed per second '
                             'to the ripe server', default=25)
    parser.add_argument('-b', '--ripe-request-burst-limit', type=int,
                        dest='ripeRequestBurstLimit',
                        help='How many request should at maximum be allowed per second'
                             ' to the ripe server', default=40)
    parser.add_argument('-l', '--logging-file', type=str, default='check_locations.log',
                        dest='log_file',
                        help='Specify a logging file where the log should be saved')
    parser.add_argument('-ll', '--log-level', type=str, default='INFO', dest='log_level',
                        choices=['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the preferred log level')


def main():
    """Main"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    global logger
    logger = util.setup_logger(args.log_file, 'eval_ProbeAPI', loglevel=args.log_level)
    logger.debug('starting')

    with open(args.locationFile) as locationFile:
        locations = util.json_load(locationFile)

    for location in locations.values():
        location.nodes = None
        location.available_nodes = None

    probe_slow_down_sema = threading.BoundedSemaphore(args.ripeRequestBurstLimit)
    probes_finish_event = threading.Event()
    probes_generator_thread = threading.Thread(target=generate_request_tokens,
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

            for i in range(0, len(threads)):
                threads.remove(threads[i])

        thread_sema.acquire()
        thread = threading.Thread(target=get_nearest_ripe_nodes,
                                  args=(location, 1000, args.ip_version, probe_slow_down_sema,
                                        thread_sema))
        thread.start()
        threads.append(thread)

        thread_sema.acquire()
        thread = threading.Thread(target=get_nearest_probeapi_probes,
                                  args=(location, 1000, probe_slow_down_sema, thread_sema))

        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    probes_finish_event.set()
    probes_generator_thread.join()

    count_dict = collections.defaultdict(int)

    for location in locations.values():
        if location.has_probeapi and location.available_nodes:
            count_dict['has_both'] += 1
        elif location.has_probeapi:
            count_dict['has_probeapi'] += 1
        elif location.available_nodes:
            count_dict['has_ripe'] += 1
        else:
            count_dict['has_none'] += 1

    print(count_dict)
    with open(args.locationFile, 'w') as locationFile:
        util.json_dump(locations, locationFile)


def generate_request_tokens(sema: threading.Semaphore, limit: int, finish_event: threading.Event):
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


def get_nearest_ripe_nodes(location: util.Location, max_distance: int, ip_version: str,
                           slow_down_sema: threading.Semaphore = None,
                           thread_sema: threading.Semaphore = None) -> \
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
            }

            slow_down_sema.acquire()
            nodes = ripe_atlas.ProbeRequest(**params)

            nodes.next_batch()
            if nodes.total_count > 0:
                results = [node for node in nodes]
                available_probes = [node for node in results
                                    if (node['status']['name'] == 'Connected' and
                                        'system-{}-works'.format(ip_version) in
                                        [tag['slug'] for tag in node['tags']] and
                                        'system-{}-capable'.format(ip_version) in
                                        [tag['slug'] for tag in node['tags']])]
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


def get_nearest_probeapi_probes(location: util.Location, max_distance: int,
                                slow_down_sema: threading.Semaphore = None,
                                thread_sema: threading.Semaphore = None):
    """
    Search for probes near the location using probeapi
    :param location: the location for which probes should be searched
    :param max_distance: the maximal distance
    :param slow_down_sema: semaphore to slow down the amount of requests per second
    :param thread_sema: end of method
    :return: nothing
    """
    try:
        if max_distance % 50 != 0:
            logger.critical('max_distance must be a multiple of 50')
            return

        distances = [100, 250, 500, 1000]
        if max_distance not in distances:
            distances.append(max_distance)
            distances.sort()

        url = util.PROBE_API_URL_GET_PROBES
        headers = {
            'apikey': util.PROBE_API_KEY,
            'Accept': 'application/json'
        }

        for distance in distances:
            if distance > max_distance:
                break

            distance_gc = math.sqrt(2 * distance**2)
            min_location = location.location_with_distance_and_bearing(distance_gc, 315)
            max_location = location.location_with_distance_and_bearing(distance_gc, 135)
            params = {
                'minLatitude': min_location.lat,
                'minLongitude': min_location.lon,
                'maxLatitude': max_location.lat,
                'maxLongitude': max_location.lon
            }

            if slow_down_sema:
                slow_down_sema.acquire()

            response = requests.get(url, params=params, headers=headers, timeout=10)

            response_dct = response.json()

            if 'GetProbesByBoundingBoxResult' not in response_dct:
                logger.warning('Error in probes request:\n{}'.format(response_dct))
                continue

            if len(response_dct['GetProbesByBoundingBoxResult']):
                location.has_probeapi = (min_location, max_location)
                return

    finally:
        if thread_sema:
            thread_sema.release()


if __name__ == '__main__':
    main()
