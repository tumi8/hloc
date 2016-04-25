#!/usr/bin/env python3
"""
This module checks the location information found with different verifing methods
"""
from __future__ import print_function
import argparse
import ujson as json
import requests
import time
import os.path
import geoip2.database
import subprocess
import random
import mmap
import sys
import IP2Location
# from pympler import tracker
import multiprocessing as mp
import ripe.atlas.cousteau
from threading import Thread, Semaphore, Lock
from math import radians, cos, sqrt, ceil
from ripe.atlas.cousteau import (
    Ping, AtlasSource, AtlasCreateRequest, AtlasResultsRequest,
    MeasurementRequest, Measurement)

from ..data_processing import util

API_KEY = '1dc0b3c2-5e97-4a87-8864-0e5a19374e60'
RIPE_SESSION = requests.Session()
MAX_RTT = 9
ALLOWED_MEASUREMENT_AGE = 60*60*24*350       # 350 days in seconds
ATLAS_URL = 'https://atlas.ripe.net'
API_MEASUREMENT_POINT = '/api/v1/measurement'
MEASUREMENT_URL = ATLAS_URL + API_MEASUREMENT_POINT + '/'

LOCATION_RADIUS = 100
LOCATION_RADIUS_PRECOMPUTED = (LOCATION_RADIUS / 6371)**2
MUNICH_ID = 'munich'
DALLAS_ID = 'dallas'
SINGAPORE_ID = 'singapore'
COORDS = {MUNICH_ID: {'lat': 48.137357, 'lon': 11.575288},
          DALLAS_ID: {'lat': 32.776664, 'lon': -96.796988},
          SINGAPORE_ID: {'lat': 1.352083, 'lon': 103.874949}}


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                        ' in the name so it is possible to format the string')
    parser.add_argument('-f', '--file-count', type=int, default=8, dest='fileCount',
                        help='number of files from preprocessing')
    parser.add_argument('-l', '--location-file-name', required=True, type=str,
                        dest='locationFile', help='The path to the location file.'
                        ' The output file from the codes_parser')
    parser.add_argument('-m', '--method', type=str, dest='verifingMethod',
                        choices=['geoip', 'ip2location', 'ripe'], default='ripe',
                        help='Specify the method with wich the locations should be checked')
    # parser.add_argument('-d', '--ripe-node-distance', type=int, dest='ripeDistance',
    #                     default=250, help='This number defines the maximum distance between'
    #                     ' a ripe probe and the suspected location.')
    parser.add_argument('-g', '--geoip-database', type=str, dest='geoipFile',
                        help='If you choose the geoip method you have to'
                        ' specify the path to the database in this argument')
    parser.add_argument('-i', '--ip2location-database', type=str, dest='ip2locFile',
                        help='If you choose the ip2location as method you have to'
                        ' specify the path to the database in this argument.\n'
                        'Currently not tested, because no database is available')
    parser.add_argument('-r', '--rtt-file-proto', type=str, dest='rtt_proto',
                        help='If specified the rtt times will be read from the file '
                        'prototype for every input file. It must '
                        'contain a rtt for every ip in the input files')
    parser.add_argument('-q', '--ripe-request-limit', type=int, dest='ripeRequestLimit',
                        help='How many request should normally be allowed per second '
                        'to the ripe server', default=10)
    parser.add_argument('-b', '--ripe-request-burst-limit', type=int, dest='ripeRequestBurstLimit',
                        help='How many request should at maximum be allowed per second'
                        ' to the ripe server', default=15)

    args = parser.parse_args()
    if args.filename_proto.find('{}') < 0:
        print(r'Wrong format for the filename! It must be formatable with the {}-brackets'
              ' where the numbers have to be inserted.', file=sys.stderr)

    if args.verifingMethod == 'geoip':
        if args.geoipFile is None:
            print('Please specify the file location of the geoip database!', file=sys.stderr)
            return 1
        if not os.path.isfile(args.geoipFile):
            print('Path to geoip database does not exist!', file=sys.stderr)
            return 1

    if args.verifingMethod == 'ip2location':
        if args.ip2locFile is None:
            print('Please specify the file location of the ip2lcation database!', file=sys.stderr)
            return 1
        if not os.path.isfile(args.ip2locFile):
            print('Path to ip2location database does not exist!', file=sys.stderr)
            return 1

    startTime = time.time()
    locations = None
    with open(args.locationFile, 'r') as locationFile:
        locations = json.load(locationFile)

    if args.verifingMethod == 'ripe':
        ripe_slow_down_sema = mp.BoundedSemaphore(args.ripeRequestBurstLimit)
        ripe_create_sema = mp.Semaphore(100)
        generator_thread = Thread(target=generate_ripe_request_tokens, args=(ripe_slow_down_sema,
                                                                             args.ripeRequestLimit))
        generator_thread.deamon = True
        if 'near_nodes' not in next(iter(locations.values())).keys():
            for key in locations.keys():
                nodes, available_nodes = get_nearest_ripe_nodes(locations[key], 1000)
                locations[key]['nodes'] = nodes
                locations[key]['near_nodes'] = available_nodes
            with open(args.locationFile, 'w') as locationFile:
                json.dump(locations, locationFile)

        null_locations = []
        for location in locations.values():
            if len(location['near_nodes']) == 0:
                null_locations.append(location)

        with open('locations_wo_nodes.json', 'w') as loc_wo_nodes_file:
            json.dump(null_locations, loc_wo_nodes_file)

        COORDS[MUNICH_ID]['distances'] = {}
        COORDS[DALLAS_ID]['distances'] = {}
        COORDS[SINGAPORE_ID]['distances'] = {}
        for location in locations.values():
            COORDS[MUNICH_ID]['distances'][str(location['id'])] = get_location_distance(
                location, COORDS[MUNICH_ID])
            COORDS[DALLAS_ID]['distances'][str(location['id'])] = get_location_distance(
                location, COORDS[DALLAS_ID])
            COORDS[SINGAPORE_ID]['distances'][str(location['id'])] = get_location_distance(
                location, COORDS[SINGAPORE_ID])

    print('finished ripe after {}'.format((time.time() - startTime)), flush=True)

    processes = []
    for pid in range(0, args.fileCount):
        process = None
        if args.verifingMethod == 'ripe':
            process = mp.Process(target=ripe_check_for_list, args=(args.filename_proto,
                                                                   pid,
                                                                   locations,
                                                                   args.rtt_proto,
                                                                   ripe_create_sema,
                                                                   ripe_slow_down_sema))
        elif args.verifingMethod == 'geoip':
            process = mp.Process(target=geoip_check_for_list, args=(args.filename_proto,
                                                                    pid,
                                                                    locations,
                                                                    args.geoipFile))
        elif args.verifingMethod == 'ip2location':
            process = mp.Process(target=ip2location_check_for_list, args=(args.filename_proto,
                                                                          pid,
                                                                          locations,
                                                                          args.ip2locFile))
        processes.append(process)

    for process in processes:
        process.start()

    generator_thread.start()

    alive = 8
    while alive > 0:
        try:
            for process in processes:
                process.join()
            process_sts = [pro.is_alive() for pro in processes]
            if process_sts.count(True) != alive:
                print(process_sts.count(True), 'processes alive')
                alive = process_sts.count(True)
        except KeyboardInterrupt:
            pass

    endTime = time.time()
    print('running time: {}'.format((endTime - startTime)))
    sys.exit(0)


def generate_ripe_request_tokens(sema, limit):
    """
    Generates RIPE_REQUESTS_PER_SECOND tokens on the Semaphore
    """
    while True:
        time.sleep(2/limit)
        try:
            sema.release()
            sema.release()
        except ValueError:
            continue


def ip2location_check_for_list(filename_proto, pid, locations, ip2locations_filename):
    """Verifies the locations with the ip2locations database"""
    ip2loc_obj = IP2Location.IP2Location()
    ip2loc_obj.open(ip2locations_filename)

    locationDomainFile = open(filename_proto.format(pid) + '.locations', 'w')

    correct_count = {'iata': 0, 'icao': 0, 'faa': 0, 'clli': 0, 'alt': 0, 'locode': 0}

    with open(filename_proto.format(pid), 'r') as domainFile:
        domain_file_mm = mmap.mmap(domainFile.fileno(), 0, prot=mmap.PROT_READ)
        line = domain_file_mm.readline().decode('utf-8')
        while len(line) > 0:
            domain_location_list = json.loads(line)
            correct_locs = []
            wrong_locs = []
            for index in range(0, len(domain_location_list)):
                matching_location = ip2loc_get_domain_location(domain_location_list[index],
                                                               ip2loc_obj,
                                                               locations,
                                                               correct_count)
                if matching_location is not None:
                    domain_location_list[index]['location'] = matching_location
                    correct_locs.append(domain_location_list[index])
                else:
                    wrong_locs.append(domain_location_list[index])
            json.dump(correct_locs, locationDomainFile, indent=4)
            locationDomainFile.write('\n')
            line = domain_file_mm.readline().decode('utf-8')


def ip2loc_get_domain_location(domain, ip2loc_reader, locations, correct_count):
    """checks the domains locations with the geoipreader"""
    ipLocation = ip2loc_reader.get_all(domain['ip'])
    for key, labelDict in domain['domainLabels'].items():
        if key == 'tld':
            continue
        # label = labelDict['label']
        for match in labelDict['matches']:
            if ipLocation.country_short == locations[str(match['location_id'])]['stateCode']:
                correct_count[match['type']] = correct_count[match['type']] + 1
                return {'location': locations[str(match['location_id'])], 'type': match['type']}
            # if is_in_radius(locations[str(match['location_id'])], ipLocation.location):
            #     correct_count[match['type']] = correct_count[match['type']] + 1
            #     return {'location': locations[str(match['location_id'])], 'type': match['type']}

    return None


def geoip_check_for_list(filename_proto, pid, locations, geoip_filename):
    """Verifies the location with the geoip database"""
    geoipreader = geoip2.database.Reader(geoip_filename)
    locationDomainFile = open(filename_proto.format(pid) + '.locations', 'w')

    correct_count = {'iata': 0, 'icao': 0, 'faa': 0, 'clli': 0, 'alt': 0, 'locode': 0}

    with open(filename_proto.format(pid), 'r') as domainFile:
        domain_file_mm = mmap.mmap(domainFile.fileno(), 0, prot=mmap.PROT_READ)
        line = domain_file_mm.readline().decode('utf-8')
        while len(line) > 0:
            domain_location_list = json.loads(line)
            correct_locs = []
            wrong_locs = []
            for index in range(0, len(domain_location_list)):
                matching_location = geoip_get_domain_location(domain_location_list[index],
                                                              geoipreader,
                                                              locations,
                                                              correct_count)
                if matching_location is not None:
                    domain_location_list[index]['location'] = matching_location
                    correct_locs.append(domain_location_list[index])
                else:
                    wrong_locs.append(domain_location_list[index])
            json.dump(correct_locs, locationDomainFile, indent=4)
            locationDomainFile.write('\n')
            line = domain_file_mm.readline().decode('utf-8')

    locationDomainFile.close()
    geoipreader.close()
    print('pid: ', pid, 'correct count: ', correct_count, flush=True)


def geoip_get_domain_location(domain, geoipreader, locations, correct_count):
    """checks the domains locations with the geoipreader"""
    geoipLocation = geoipreader.city(domain['ip'])
    if (geoipLocation.location is None or geoipLocation.location.longitude is None or
            geoipLocation.location.latitude is None):
        return None
    for key, labelDict in domain['domainLabels'].items():
        if key == 'tld':
            continue

        for match in labelDict['matches']:
            if is_in_radius(locations[str(match['location_id'])], geoipLocation.location):
                correct_count[match['type']] = correct_count[match['type']] + 1
                return {'location': locations[str(match['location_id'])], 'type': match['type']}

    return None


def is_in_radius(location1, location2):
    """
    Calculate the distance (km) between two points
    using the equirectangular distance approximation
    location1 is the location saved in our way
    location2 is the location object from geoip2
    """
    lon1 = radians(float(location1['lon']))
    lat1 = radians(float(location1['lat']))
    lon2 = radians(float(location2.longitude))
    lat2 = radians(float(location2.latitude))
    # Radius of earth in kilometers. Use 3956 for miles
    return LOCATION_RADIUS_PRECOMPUTED >= (((lon2 - lon1) * cos(0.5*(lat2+lat1)))**2 +
                                           (lat2 - lat1)**2)


def get_location_distance(location1, location2):
    """
    Calculate the distance (km) between two points
    using the equirectangular distance approximation
    location1 is the location saved in our way
    location2 is the location saved in our dict
    """
    lon1 = radians(float(location1['lon']))
    lat1 = radians(float(location1['lat']))
    lon2 = radians(float(location2['lon']))
    lat2 = radians(float(location2['lat']))

    return sqrt(((lon2 - lon1) * cos(0.5*(lat2+lat1)))**2 + (lat2 - lat1)**2) * 6371


def ripe_check_for_list(filename_proto, pid, locations, rtt_proto,
                        ripe_create_sema, ripe_slow_down_sema):
    """Checks for all domains if the suspected locations are correct"""
    thread_count = 25
    thread_semaphore = Semaphore(thread_count)

    count_lock = Lock()
    correct_count = {'iata': 0, 'icao': 0, 'faa': 0, 'clli': 0, 'alt': 0, 'locode': 0}

    def update_count_for_type(ctype):
        """acquires lock and increments in count the type property"""
        with count_lock:
            correct_count[ctype] = correct_count[ctype] + 1

    chair_server_locks = {'m': Lock(), 's': Lock(), 'd': Lock()}
    rtts = None
    if rtt_proto is not None:
        with open(rtt_proto.format(pid), 'r') as rtt_file:
            rtts = json.load(rtt_file)

    domain_lock = Lock()
    domains = {CORRECT_TYPE: [], NOT_RESPONDING_TYPE: [], NO_LOCATION_TYPE: [],
               BLACKLISTED_TYPE: []}

    domain_output_file = open('check_domains_output_{}.json'.format(pid), 'w', buffering=1)

    # @profile
    def dump_domain_list():
        """Write all domains in the buffer to the file and empty the lists"""
        print('pid', pid, 'correct', len(domains[CORRECT_TYPE]),
              'not_responding', len(domains[NOT_RESPONDING_TYPE]),
              'no_location', len(domains[NO_LOCATION_TYPE]),
              'blacklisted', len(domains[BLACKLISTED_TYPE]), flush=True)
        domain_output_file.write(json.dumps(domains) + '\n')
        del domains[CORRECT_TYPE]
        del domains[NOT_RESPONDING_TYPE]
        del domains[NO_LOCATION_TYPE]
        del domains[BLACKLISTED_TYPE]
        domains[CORRECT_TYPE] = []
        domains[NOT_RESPONDING_TYPE] = []
        domains[NO_LOCATION_TYPE] = []
        domains[BLACKLISTED_TYPE] = []

    def update_domains(domain, dtype):
        """Append current domain in the domain dict to the dtype"""
        domain_lock.acquire()
        domains[dtype].append(domain)

        if (len(domains[CORRECT_TYPE]) + len(domains[NOT_RESPONDING_TYPE]) +
                len(domains[NO_LOCATION_TYPE]) + len(domains[BLACKLISTED_TYPE])) >= 10 ** 3:
            dump_domain_list()

        domain_lock.release()

    threads = []
    try:
        with open(filename_proto.format(pid), 'r') as domainFile:
            domain_file_mm = mmap.mmap(domainFile.fileno(), 0, prot=mmap.PROT_READ)
            line = domain_file_mm.readline().decode('utf-8')
            count_entries = 0
            while len(line) > 0:
                domain_location_list = json.loads(line)
                if len(threads) > thread_count:
                    remove_indexes = []
                    for t_index in range(0, len(threads)):
                        if not threads[t_index].is_alive():
                            threads[t_index].join()
                            remove_indexes.append(t_index)
                    for r_index in remove_indexes[::-1]:
                        threads.remove(threads[r_index])
                for domain in domain_location_list:
                    thread_semaphore.acquire()
                    thread = Thread(target=check_domain_location_ripe,
                                    args=(pid, domain, update_domains,
                                          update_count_for_type, thread_semaphore,
                                          locations, chair_server_locks, rtts,
                                          ripe_create_sema, ripe_slow_down_sema))
                    thread.start()
                    threads.append(thread)
                    count_entries = count_entries + 1
                    if count_entries % 10000 == 0:
                        print('pid', pid, 'count', count_entries, 'correct_count',
                              correct_count, flush=True)
                line = domain_file_mm.readline().decode('utf-8')

            domain_file_mm.close()
    except KeyboardInterrupt:
        pass

    for thread in threads:
        thread.join()

    json.dump(domains, domain_output_file)
    print('pid', pid, 'correct_count', correct_count, flush=True)


CORRECT_TYPE = 'correct'
NOT_RESPONDING_TYPE = 'not_responding'
NO_LOCATION_TYPE = 'no_location'
BLACKLISTED_TYPE = 'blacklisted'


class Locationresult(object):
    """Stores the result for a location"""

    def __init__(self, location_id, lat, lon, rtt):
        super(Locationresult, self).__init__()
        self.location_id = location_id
        self.lat = lat
        self.lon = lon
        self.rtt = rtt

    def location_dict(self):
        """Returns a dict with the location like {'lat': lat, 'lon': lon}"""
        return {'lat': self.lat, 'lon': self.lon}


def check_domain_location_ripe(pid, domain, update_domains, update_count_for_type,
                               sema, locations, chair_server_locks,
                               rtts, ripe_create_sema, ripe_slow_down_sema):
    """checks if ip is at location"""
    try:
        matched = False

        results = None
        if rtts is not None and domain['ip'] in rtts.keys():
            if rtts[domain['ip']]['blacklisted']:
                update_domains(domain, BLACKLISTED_TYPE)
                return

            results = []
            results.append(Locationresult(MUNICH_ID,
                                          COORDS[MUNICH_ID]['lat'],
                                          COORDS[MUNICH_ID]['lon'],
                                          rtts[domain['ip']]['rtt'][MUNICH_ID]))
            results.append(Locationresult(SINGAPORE_ID,
                                          COORDS[SINGAPORE_ID]['lat'],
                                          COORDS[MUNICH_ID]['lon'],
                                          rtts[domain['ip']]['rtt'][SINGAPORE_ID]))
            results.append(Locationresult(DALLAS_ID,
                                          COORDS[DALLAS_ID]['lat'],
                                          COORDS[MUNICH_ID]['lon'],
                                          rtts[domain['ip']]['rtt'][DALLAS_ID]))
        else:
            results = test_netsec_server(domain['ip'], chair_server_locks)
        if results is None or len([res for res in results if res.rtt is not None]) == 0:
            update_domains(domain, NOT_RESPONDING_TYPE)
            return

        measurements = [mes for mes in get_measurements(domain['ip'], ripe_slow_down_sema)]
        print('pid', pid, 'ip', domain['ip'], 'got measurements',
              len(measurements), flush=True)

        for key in domain['domainLabels'].keys():
            if key == 'tld':
                continue
            # # Test without considering the first domain level label
            # if key == '0':
            #     continue

            matches = domain['domainLabels'][key]['matches'][:]

            def get_next_match(matches):
                matches = sort_matches(matches, results, locations)
                ret = None
                if len(matches) > 0:
                    ret = matches[0]
                return ret

            next_match = get_next_match(matches)
            while next_match is not None:
                location = locations[next_match['location_id']]
                near_nodes = location['near_nodes']

                if len(near_nodes) == 0:
                    matches.remove(next_match)
                    next_match = get_next_match(matches)
                    continue

                chk_m, node = check_measurements_for_nodes(measurements, location,
                                                           results, ripe_slow_down_sema)

                if node is not None:
                    node_location_dist = get_location_distance(
                        {'lat': node['latitude'], 'lon': node['longitude']}, location)
                if chk_m is None or chk_m == -1:
                    # print('make measurement', flush=True)
                    # only if no old measurement exists
                    m_results, near_node = create_and_check_measurement(domain['ip'],
                                                                        location,
                                                                        near_nodes,
                                                                        ripe_create_sema,
                                                                        ripe_slow_down_sema)
                    if near_node is not None:
                        node_location_dist = get_location_distance(
                            {'lat': near_node['latitude'], 'lon': near_node['longitude']}, location)
                    if m_results is None:
                        matches.remove(next_match)
                        next_match = get_next_match(matches)
                        continue

                    result = next(iter(m_results), None)

                    if result is None:
                        matches.remove(next_match)
                        next_match = get_next_match(matches)
                        continue

                    chk_res = get_rtt_from_result(result)

                    if chk_res == -1:
                        update_domains(domain, NOT_RESPONDING_TYPE)
                        return
                    if chk_res is None:
                        matches.remove(next_match)
                        next_match = get_next_match(matches)
                        continue
                    elif chk_res < (MAX_RTT + node_location_dist / 100):
                        update_count_for_type(next_match['type'])
                        matched = True
                        domain['correctMatch'] = next_match
                        domain['testedNode'] = near_node
                        update_domains(domain, CORRECT_TYPE)
                        break
                    else:
                        n_res = Locationresult(location['id'], location['lat'],
                                               location['lon'], chk_res)
                        results.append(n_res)
                elif chk_m < (MAX_RTT + node_location_dist / 100):
                    # print('measurements fetched', flush=True)
                    update_count_for_type(next_match['type'])
                    matched = True
                    domain['correctMatch'] = next_match
                    domain['testedNote'] = node
                    update_domains(domain, CORRECT_TYPE)
                    break
                else:
                    # print('measurements fetched', flush=True)
                    n_res = Locationresult(location['id'], location['lat'], location['lon'],
                                           chk_m)
                    results.append(n_res)

                matches.remove(next_match)
                next_match = get_next_match(matches)

            if matched:
                break

        if not matched:
            update_domains(domain, NO_LOCATION_TYPE)
    finally:
        sema.release()


def sort_matches(matches, results, locations):
    """Sort the matches after their most probable location"""
    results = [result for result in results if result.rtt is not None]
    results.sort(key=lambda res: res.rtt)
    if len(results) == 0:
        return matches

    near_matches = {}
    for match in matches:
        distances = []
        for result in results:
            if result.location_id in COORDS.keys():
                distance = COORDS[result.location_id]['distances'][match['location_id']]
                if distance > (result.rtt * 100):
                    break
                distances.append((result, distance))
            else:
                distance = get_location_distance(locations[match['location_id']],
                                                 result.location_dict())
                if distance > (result.rtt * 100):
                    break
                distances.append((result, distance))
        if len(distances) != len(results):
            continue

        min_res = min(distances, key=lambda res: res[1])[0]

        if min_res.location_id not in near_matches.keys():
            near_matches[min_res.location_id] = []

        near_matches[min_res.location_id].append(match)

    ret = []
    for result in results:
        if result.location_id in near_matches.keys():
            ret.extend(near_matches[result.location_id])
    return ret


def test_netsec_server(ip_address, chair_server_locks):
    """Test from the network chairs server the rtts and returns them in a dict"""
    ret = []
    server_configs = {'m': {'user': 'root', 'port': 15901, 'server': 'planetlab7.net.in.tum.de'},
                      's': {'user': 'root', 'port': None, 'server': '139.162.29.117'},
                      'd': {'user': 'root', 'port': None, 'server': '45.33.5.55'}}
    chair_server_locks['m'].acquire()
    ret.append(Locationresult(MUNICH_ID, COORDS[MUNICH_ID]['lat'], COORDS[MUNICH_ID]['lon'],
                              get_min_rtt(ssh_ping(server_configs['m'], ip_address))))
    chair_server_locks['m'].release()
    chair_server_locks['s'].acquire()
    ret.append(Locationresult(SINGAPORE_ID, COORDS[SINGAPORE_ID]['lat'],
                              COORDS[SINGAPORE_ID]['lon'],
                              get_min_rtt(ssh_ping(server_configs['s'], ip_address))))
    chair_server_locks['s'].release()
    chair_server_locks['d'].acquire()
    ret.append(Locationresult(DALLAS_ID, COORDS[DALLAS_ID]['lat'], COORDS[DALLAS_ID]['lon'],
                              get_min_rtt(ssh_ping(server_configs['d'], ip_address))))
    chair_server_locks['d'].release()
    if ret[0].rtt is None and ret[1].rtt is None and ret[2].rtt is None:
        return None
    return ret


def ssh_ping(server_conf, ip_address):
    """Perform a ping from the server with server_conf over ssh"""
    # build ssh arguments
    args = ['ssh']
    if server_conf['port'] is not None:
        args.append('-p')
        args.append(str(server_conf['port']))
    args.append('{0}@{1}'.format(server_conf['user'], server_conf['server']))
    args.extend(['ping', '-fnc', '4', ip_address])  # '-W 1',
    output = None
    try:
        output = subprocess.check_output(args, timeout=45)
    except subprocess.CalledProcessError as error:
        if error.returncode == 1:
            return None
        elif error.returncode == 255:
            time.sleep(3)
            return ssh_ping(server_conf, ip_address)
        print(error.output, flush=True, file=sys.stderr)
        raise error
    except subprocess.TimeoutExpired:
        return None
    except:
        raise
    return str(output)


def get_min_rtt(ping_output):
    """
    parses the min rtt from a ping output
    if the host did not respond returns None
    """
    if ping_output is None:
        return None
    min_rtt_str = ping_output[(ping_output.find('mdev = ') + len('mdev = ')):]
    min_rtt_str = min_rtt_str[:min_rtt_str.find('/')]
    return float(min_rtt_str)


def get_rtt_from_result(measurement_entry):
    """gets the rtt from measurement_entry"""
    if 'min' in measurement_entry.keys():
        return measurement_entry['min']
    if 'result' in measurement_entry.keys() and len(measurement_entry['rtt']) > 0:
        min_rtt = min(measurement_entry['rtt'], key=lambda res: res['rtt'])['rtt']
        return min_rtt
    if 'avg' in measurement_entry.keys():
        return measurement_entry['avg']
    return None


NON_WORKING_PROBES = []
NON_WORKING_PROBES_LOCK = Lock()


def create_and_check_measurement(ip_addr, location, near_nodes, ripe_create_sema,
                                 ripe_slow_down_sema):
    """creates a measurement for the parameters and checks for the created measurement"""
    near_nodes = [node for node in near_nodes if node not in NON_WORKING_PROBES]

    def new_near_node():
        """Get a node from the near_nodes and return it"""
        if len(near_nodes) > 0:
            return near_nodes[random.randint(0, len(near_nodes) - 1)]
        else:
            return None

    near_node = new_near_node()
    if near_node is None:
        return (None, None)

    def new_measurement():
        """Create new measurement"""
        return create_ripe_measurement(ip_addr, location, near_node, ripe_slow_down_sema)

    def sleep_ten():
        """Sleep for ten seconds"""
        time.sleep(10)

    ripe_create_sema.acquire()
    try:
        measurement_id = new_measurement()
        if measurement_id is None:
            return (None, None)

        while True:
            if measurement_id is None:
                return (None, None)
            res = get_ripe_measurement(measurement_id)
            if res is not None:
                if res.status_id == 4:
                    break
                elif res.status_id in [6, 7]:
                    NON_WORKING_PROBES_LOCK.acquire()
                    NON_WORKING_PROBES.append(near_node)
                    NON_WORKING_PROBES_LOCK.release()
                    near_nodes.remove(near_node)
                    near_node = new_near_node()
                    if near_node is None:
                        return (None, None)
                    measurement_id = new_measurement()
                    continue
                elif res.status_id in [0, 1, 2]:
                    sleep_ten()
            else:
                sleep_ten()
        ripe_slow_down_sema.acquire()
        success, m_results = AtlasResultsRequest(**{'msm_id': measurement_id}).create()
        while not success:
            print('ResultRequest error', m_results, flush=True, file=sys.stderr)
            time.sleep(10 + (random.randrange(0, 500) / 100))
            ripe_slow_down_sema.acquire()
            success, m_results = AtlasResultsRequest(**{'msm_id': measurement_id}).create()

        return (m_results, near_node)

    finally:
        ripe_create_sema.release()


USE_WRAPPER = True


def create_ripe_measurement(ip_addr, location, near_node, ripe_slow_down_sema):
    """Creates a new ripe measurement to the first near node and returns the measurement id"""

    def create_ripe_measurement_wrapper(ip_addr, location, near_node, ripe_slow_down_sema):
        """Creates a new ripe measurement to the first near node and returns the measurement id"""

        ping = Ping(af=4, packets=1, target=ip_addr,
                    description=ip_addr + ' test for location ' + location['cityName'])
        source = AtlasSource(value=str(near_node['id']), requested=1, type='probes')
        atlas_request = AtlasCreateRequest(
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

            retries = retries + 1
            if retries % 5 == 0:
                print('Create error', response, flush=True, file=sys.stderr)

        measurement_ids = response['measurements']
        return measurement_ids[0]

    def create_ripe_measurement_post(ip_addr, location, near_node, ripe_slow_down_sema):
        """Creates a new ripe measurement to the first near node and returns the measurement id"""
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        payload = {
            'definitions': [
                {
                    'target': ip_addr,
                    'af': 4,
                    'packets': 1,
                    'size': 48,
                    'description': ip_addr + ' test for location ' + location['cityName'],
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
            'is_oneoff': True
            }

        params = {'key': API_KEY}
        ripe_slow_down_sema.acquire()
        response = requests.post('https://atlas.ripe.net/api/v1/measurement/', params=params,
                                 headers=headers, json=payload)

        retries = 0
        while response.status_code != 202 and retries < 5:
            if response.status_code == 400:
                print('Create measurement error!', response.text, flush=True, file=sys.stderr)
                return None
            ripe_slow_down_sema.acquire()
            response = requests.post('https://atlas.ripe.net/api/v1/measurement/', params=params,
                                     headers=headers, json=payload)
            if response.status_code != 202:
                retries = retries + 1

        if response.status_code != 202:
            response.raise_for_status()

        measurement_ids = response.json()['measurements']
        return measurement_ids[0]

    if USE_WRAPPER:
        return create_ripe_measurement_wrapper(ip_addr, location, near_node, ripe_slow_down_sema)
    else:
        return create_ripe_measurement_post(ip_addr, location, near_node, ripe_slow_down_sema)


def get_measurements(ip_addr, ripe_slow_down_sema):
    """
    Get ripe measurements for ip_addr
    """
    def next_batch(measurement):
        retries = 0
        while True:
            try:
                measurement.next_batch()
            except ripe.atlas.cousteau.exceptions.APIResponseError:
                pass
            else:
                break

            time.sleep(5)
            retries = retries + 1

            if retries % 5 == 0:
                print('Ripe next_batch error!', ip_addr, flush=True, file=sys.stderr)
    max_age = int(time.time()) - ALLOWED_MEASUREMENT_AGE
    params = {'status': '2,4,5',
              'target_ip': ip_addr,
              'type': 'ping',
              'stop_time__gte': max_age}
    ripe_slow_down_sema.acquire()
    retries = 0
    while True:
        try:
            measurements = MeasurementRequest(**params)
        except ripe.atlas.cousteau.exceptions.APIResponseError:
            pass
        else:
            break

        time.sleep(5)
        retries = retries + 1

        if retries % 5 == 0:
            print('Ripe MeasurementRequest error!', ip_addr, flush=True, file=sys.stderr)
    next_batch(measurements)
    if measurements.total_count > 200:
        skip = ceil(measurements.total_count / 100) - 2

        for _ in range(0, skip):
            next_batch(measurements)

    return measurements


def get_measurements_for_nodes(measurements, ripe_slow_down_sema, near_nodes):
    """Loads all results for all measurements if they are less than a year ago"""

    for measure in measurements:
        allowed_start_time = int(time.time()) - ALLOWED_MEASUREMENT_AGE

        params = {'msm_id': measure['id'], 'start': allowed_start_time,
                  'probe_ids': [node['id'] for node in near_nodes]}
        ripe_slow_down_sema.acquire()
        success, result_list = AtlasResultsRequest(**params).create()
        retries = 0
        while not success and retries < 5:
            time.sleep(10 + (random.randrange(0, 500) / 100))
            ripe_slow_down_sema.acquire()
            success, result_list = AtlasResultsRequest(**params).create()
            if not success:
                retries = retries + 1

        if retries > 4:
            print('AtlasResultsRequest error!', result_list, flush=True, file=sys.stderr)
            continue

        # measure['results'] = result_list
        yield {'msm_id': measure['id'], 'results': result_list}


def check_measurements_for_nodes(measurements, location, results, ripe_slow_down_sema):
    """
    Check the measurements list for measurements from near_nodes
    """
    if measurements is None or len(measurements) == 0:
        return (None, None)

    measurement_results = get_measurements_for_nodes(measurements,
                                                     ripe_slow_down_sema,
                                                     location['nodes'])

    check_n = None
    node_n = None
    near_node_ids = [node['id'] for node in location['nodes']]
    for m_results in measurement_results:
        for result in m_results['results']:
            oldest_alowed_time = int(time.time()) - ALLOWED_MEASUREMENT_AGE
            if (result['prb_id'] not in near_node_ids or
                    result['timestamp'] < oldest_alowed_time):
                continue
            check_res = get_rtt_from_result(result)
            if check_res is None:
                continue
            if check_res == -1 and check_n is None:
                check_n = check_res
            elif check_n is None or check_res < check_n or check_n == -1:
                node_n = next((near_node for near_node in location['nodes']
                               if near_node['id'] == result['prb_id']), None)
                check_n = check_res
                results.append(Locationresult(location['id'], location['lat'],
                                              location['lon'], check_res))

    if check_n is not None:
        return (check_n, node_n)

    return (None, None)


def get_ripe_measurement(measurement_id):
    """Call the RIPE measurement entry point to get the ripe measurement with measurement_id"""
    retries = 0
    while True:
        try:
            return Measurement(id=measurement_id)
        except ripe.atlas.cousteau.exceptions.APIResponseError:
            pass

        time.sleep(5)
        retries = retries + 1

        if retries % 5 == 0:
            print('Ripe get Measurement error!', measurement_id, flush=True, file=sys.stderr)


def json_request_get_wrapper(url, ripe_slow_down_sema, params=None, headers=None):
    """Performs a GET request and returns the response dict assuming the answer is json encoded"""
    response = None
    for _ in range(0, 3):
        try:
            if ripe_slow_down_sema is not None:
                ripe_slow_down_sema.acquire()
            response = RIPE_SESSION.get(url, params=params, headers=headers, timeout=(3.05, 27.05))
            break
        except requests.exceptions.ReadTimeout:
            continue

    if response is None or response.status_code >= 500:
        return None
    if response.status_code // 100 != 2:
        response.raise_for_status()

    return response.json()


def get_nearest_ripe_nodes(location, max_distance):
    """Searches for ripe nodes near the location"""
    if max_distance % 50 != 0:
        print('max_distance must be a multiple of 50', flush=True, file=sys.stderr)
        return (None, None)

    distances = [25, 50, 100, 250, 500, 1000]
    if max_distance not in distances:
        distances.append(max_distance)
        distances.sort()

    response_dict = {}
    for distance in distances:
        if distance > max_distance:
            break
        params = {'centre': '{0},{1}'.format(location['lat'], location['lon']),
                  'distance': str(distance)}

        # TODO use wrapper class
        response_dict = json_request_get_wrapper('https://atlas.ripe.net/api/v1/probe/',
                                                 None, params=params)
        if response_dict is not None and response_dict['meta']['total_count'] > 0:
            # FIXME load all nodes
            results = response_dict['objects']
            available_probes = [node for node in response_dict['objects']
                                if (node['status_name'] == 'Connected' and
                                    'system-ipv4-works' in node['tags'] and
                                    'system-ipv4-capable' in node['tags'])]
            if len(results) > 0:
                return (results, available_probes)
    return ([], [])


if __name__ == '__main__':
    main()
