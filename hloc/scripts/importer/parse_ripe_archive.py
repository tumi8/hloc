#!/usr/bin/env python3
"""
Parse data from the ripe archive files
"""

import argparse
import bz2
import collections
import datetime
import enum
import ipaddress
import ujson as json
import mmap
import multiprocessing as mp
import os
import queue
import re
import requests
import subprocess
import sys
import threading
import typing

from hloc import util
from hloc.db_utils import create_session_for_process, probe_for_id, location_for_coordinates
from hloc.models import RipeMeasurementResult, RipeAtlasProbe, Session, MeasurementProtocol, \
    MeasurementError, MeasurementResult

logger = None


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('archive_path', type=str,
                        help='Path to the directory with the archive files')
    parser.add_argument('-p', '--number-processes', type=int, default=4,
                        help='specify the number of processes used')
    parser.add_argument('-r', '--file-regex', type=str, default=r'(ping|traceroute).*\.bz2$')
    parser.add_argument('-t', '--plaintext', action='store_true', help='Use plaintext filereading')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('--days-in-past', type=int, default=30,
                        help='The number of days in the past for which parsing will be done')
    parser.add_argument('-l', '--logging-file', type=str, default='ripe-archive-import.log',
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
    logger = util.setup_logger(args.logging_file, 'parse_ripe_archive')

    if not os.path.isdir(args.archive_path):
        print('Archive path does not lead to a directory', file=sys.stderr)
        return 1

    filenames = get_filenames(args.archive_path, args.file_regex)

    Session = create_session_for_process()
    db_session = Session()
    probe_dct = get_probes(db_session)

    processes = []

    for i in range(args.number_processes):
        process = mp.Process(target=parse_ripe_data, args=(filenames, not args.plaintext,
                                                           args.days_in_past, args.debug,
                                                           probe_dct),
                             name='parse ripe data {}'.format(i))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()


def get_probes(db_session: Session) -> typing.Dict[str, RipeAtlasProbe]:
    yesterday = datetime.date.today() - datetime.timedelta(days=1)
    probe_archive_url = "https://ftp.ripe.net/ripe/atlas/probes/archive/" + \
                        yesterday.strftime('%Y/%m/%Y%m%d') + ".json.bz2"

    ripe_response = requests.get(probe_archive_url)

    if ripe_response.status_code != 200:
        ripe_response.raise_for_status()

    probe_str = bz2.decompress(ripe_response.content)
    probes_dct_list = json.loads(probe_str)['objects']
    return_dct = {}

    for probe_dct in probes_dct_list:
        if probe_dct['total_uptime'] > 0 and probe_dct['latitude'] and probe_dct['longitude']:
            probe = parse_probe(probe_dct, db_session)
            return_dct[str(probe.probe_id)] = probe

    db_session.add_all(return_dct.values())
    db_session.commit()

    return return_dct


def get_filenames(archive_path: str, file_regex: str) -> mp.Queue:
    filename_queue = mp.Queue()
    file_regex_obj = re.compile(file_regex, flags=re.MULTILINE)

    for dirname, _, filenames in os.walk(archive_path):
        for filename in filenames:
            if file_regex_obj.match(filename):
                filename_queue.put(os.path.join(dirname, filename))

    return filename_queue


class MeasurementKey(enum.Enum):
    address_fam = 'af'
    destination = 'dst_addr'
    source = 'from'
    source_alt = 'source_addr'
    measurement_id = 'msm_id'
    probe_id = 'prb_id'
    protocol = 'proto'
    result = 'result'
    hop = 'hop'
    rtt = 'rtt'
    ttl = 'ttl'
    min_rtt = 'min'
    type = 'type'
    timestamp = 'timestamp'
    error = 'err'


# @util.cprofile('ripe_parser')
def parse_ripe_data(filenames: mp.Queue, bz2_compressed: bool, days_in_past: int, debugging: bool,
                    probe_dct: typing.Dict[int, RipeAtlasProbe]):
    Session = create_session_for_process()
    db_session = Session()

    try:
        while True:
            filename = filenames.get(timeout=1)

            file_date_str = str(os.path.basename(filename).split('.')[0][-10:])
            modification_time = datetime.datetime.strptime(file_date_str, '%Y-%m-%d')

            if abs((modification_time - datetime.datetime.now()).days) >= days_in_past:
                continue

            logger.info('parsing {}'.format(filename))

            results = collections.defaultdict(dict)
            count = 0

            if bz2_compressed:
                line_queue = queue.Queue(10**5)
                finished_reading = threading.Event()
                read_thread = threading.Thread(target=read_bz2_file_queued,
                                               args=(line_queue, filename, finished_reading,
                                                     days_in_past),
                                               name='bz2 read thread')
                read_thread.start()

                def line_generator():
                    try:
                        rline = line_queue.get(timeout=2)
                    except queue.Empty:
                        logger.exception('empty queue for {}'.format(filename))
                        return

                    status_msg = False
                    read_fails = 0
                    while True:
                        if rline:
                            yield rline
                        if finished_reading.is_set() and (line_queue.empty() or read_fails == 5):
                            return
                        if finished_reading.is_set() and not status_msg:
                            logger.debug('reading finished finishing processing')
                            status_msg = True
                        rline = None
                        try:
                            rline = line_queue.get(timeout=2)
                            read_fails = 0
                            if status_msg:
                                logger.debug('processing after end of reading: {}'.format(rline))
                        except queue.Empty:
                            logger.debug('failed reading')
                            read_fails += 1

                for line in line_generator():
                    measurement_result_dct = json.loads(line)

                    measurement_result = parse_measurement(measurement_result_dct, probe_dct)

                    if measurement_result:
                        if measurement_result.probe_id not in \
                                results[measurement_result.destination_address] or \
                                results[measurement_result.destination_address][
                                    measurement_result.probe_id].min_rtt > \
                                measurement_result.min_rtt:
                            results[measurement_result.destination_address][
                                measurement_result.probe_id] = measurement_result

                            count += 1

                            if count % 10**5 == 0:
                                logger.info('parsed measurements'.format(count))

                read_thread.join()
            else:
                with open(filename) as ripe_archive_filedesc, \
                    mmap.mmap(ripe_archive_filedesc.fileno(), 0,
                              access=mmap.ACCESS_READ) as ripe_archive_file:
                    line = ripe_archive_file.readline().decode('utf-8')

                    while len(line) > 0:
                        measurement_result_dct = json.loads(line)

                        measurement_result = parse_measurement(measurement_result_dct,
                                                               probe_dct)

                        if measurement_result:
                            if measurement_result.probe_id not in \
                                    results[measurement_result.destination_address] or \
                                    results[measurement_result.destination_address][
                                    measurement_result.probe_id].min_rtt > \
                                    measurement_result.min_rtt:
                                results[measurement_result.destination_address][
                                    measurement_result.probe_id] = measurement_result

                                count += 1

                                if count % 10 ** 5 == 0:
                                    logger.info('parsed measurements'.format(count))

                        line = ripe_archive_file.readline().decode('utf-8')

            measurement_results = []
            for probe_measurement_dct in results.values():
                measurement_results.extend(probe_measurement_dct.values())

            db_session.bulk_save_objects(measurement_results)
            logger.info('parsed and saved {} measurements'.format(count))
            db_session.commit()

            if debugging:
                break

    except queue.Empty:
        pass

    db_session.commit()

    db_session.close()
    Session.remove()

    logger.info('finished parsing')


def read_bz2_file_queued(line_queue: queue.Queue, filename: str, finished_reading: threading.Event,
                         days_in_past: int):
    oldest_date_allowed = int((datetime.datetime.now() - datetime.timedelta(days=days_in_past))
                              .timestamp())
    if 'traceroute' in filename:
        command = 'bzcat ' + filename + ' | jq -c \'. | select(.timestamp >= ' + \
                  str(oldest_date_allowed) + ' and has("dst_addr")) | {timestamp: .timestamp, ' \
                  'dst_addr: .dst_addr, from: .from, msm_id: .msm_id, type: .type, ' \
                  'result: [.result[] | select(has("result")) | {result: [.result[] | ' \
                  'select(has("rtt") and has("from") and .rtt < 30) | ' \
                  '{rtt: .rtt, ttl: .ttl, from: .from}] | group_by(.from) | ' \
                  'map(min_by(.rtt)), hop: .hop}] | map(select(.result | length > 0)), ' \
                  'proto: .proto, src_addr: .src_addr, prb_id: .prb_id} | ' \
                  'select(.result | length > 0)\''
    else:
        command = 'bzcat ' + filename + ' | jq -c \'. | select(.timestamp >= ' + \
                  str(oldest_date_allowed) + ' and has("dst_addr")) | {timestamp: .timestamp, ' \
                  'avg: .avg, dst_addr: .dst_addr, from: .from, min: .min, msm_id: .msm_id, ' \
                  'type: .type, result: [.result[] | select(has("rtt") and .rtt <= 30) | .rtt] ' \
                  '| min, proto: .proto, src_addr: .src_addr, ttl: .ttl, prb_id: .prb_id} ' \
                  '| select(.result >= 0)\''

    logger.debug('reading bz2 compressed file command:\n\n{}\n\n'.format(command))
    with subprocess.Popen(command, stdout=subprocess.PIPE, shell=True, universal_newlines=True,
                          bufsize=1) as subprocess_call:
        for line in subprocess_call.stdout:
            line_queue.put(line)

    logger.debug('finished reading {}'.format(filename))
    finished_reading.set()


def parse_probe(probe_dct: typing.Dict[str, typing.Any],
                db_session: Session) -> RipeAtlasProbe:
    probe_id = probe_dct['id']
    probe_db_obj = probe_for_id(str(probe_id), db_session)

    if probe_db_obj and \
            probe_db_obj.location.gps_distance_haversine_plain(
                probe_dct['latitude'], probe_dct['longitude']) < 2:
        return probe_db_obj

    location = location_for_coordinates(probe_dct['latitude'],
                                        probe_dct['longitude'],
                                        db_session)

    probe_db_obj = RipeAtlasProbe(probe_id=probe_id, location=location)

    return probe_db_obj


def parse_measurement(measurement_result: dict, probe_dct: [int, RipeAtlasProbe]) \
        -> typing.Optional[MeasurementResult]:
    timestamp = datetime.datetime.fromtimestamp(
        measurement_result[MeasurementKey.timestamp.value])

    probe_id = str(measurement_result[MeasurementKey.probe_id.value])

    if probe_id not in probe_dct:
        return None

    probe = probe_dct[probe_id]

    destination = measurement_result[MeasurementKey.destination.value]

    behind_nat = False

    if MeasurementKey.source.value in measurement_result and \
            MeasurementKey.source_alt.value in measurement_result:
        behind_nat = probe.is_rfc_1918()

    if MeasurementKey.source.value in measurement_result:
        source = measurement_result[MeasurementKey.source.value]
    elif MeasurementKey.source_alt.value in measurement_result:
        source = measurement_result[MeasurementKey.source_alt.value]
    else:
        raise ValueError('source not found {}'.format(str(measurement_result)))

    if not source:
        source = None

    protocol = None
    if MeasurementKey.protocol.value in measurement_result:
        protocol = MeasurementProtocol(measurement_result[MeasurementKey.protocol.value].lower())

    measurement_id = measurement_result[MeasurementKey.measurement_id.value]

    if measurement_result[MeasurementKey.type.value] == 'ping':
        rtt = measurement_result[MeasurementKey.result.value]

        result = RipeMeasurementResult()
        result.probe_id = probe.id
        result.timestamp = timestamp
        result.destination_address = destination
        result.source_address = source
        result.behind_nat = behind_nat
        result.rtt = rtt
        result.protocol = protocol
        result.ripe_measurement_id = measurement_id

        if not rtt:
            result.error_msg = MeasurementError.not_reachable

        return result
    elif measurement_result[MeasurementKey.type.value] == 'traceroute':
        destination_rtts, second_hop_latency = parse_traceroute_results(measurement_result)

        for dest, rtt_ttl_tuple in destination_rtts.items():
            rtt, ttl = rtt_ttl_tuple

            result = RipeMeasurementResult()
            result.from_traceroute = True
            result.probe_id = probe.id
            result.timestamp = timestamp
            result.destination_address = destination
            result.source_address = source
            result.behind_nat = behind_nat
            result.rtt = rtt
            result.ttl = ttl
            result.protocol = protocol
            result.ripe_measurement_id = measurement_id

            if second_hop_latency and (not probe.second_hop_latency
                                       or probe.second_hop_latency > second_hop_latency):
                probe.second_hop_latency = second_hop_latency

            if not rtt:
                result.error_msg = MeasurementError.not_reachable

            return result


def parse_traceroute_results(measurement_result: typing.Dict[str, typing.Any]) \
        -> typing.Tuple[typing.DefaultDict[str, typing.Tuple[float, int]], typing.Optional[float]]:
    rtts = collections.defaultdict(tuple)
    second_hop_latency = None

    for result in measurement_result[MeasurementKey.result.value]:
        hop_count = 0

        for inner_result in result[MeasurementKey.result.value]:
            if ipaddress.ip_address(inner_result[MeasurementKey.source.value]).is_private:
                continue

            hop_count += 1
            if hop_count >= 2 and \
                    (not second_hop_latency or
                     inner_result[MeasurementKey.rtt.value] < second_hop_latency):
                second_hop_latency = inner_result[MeasurementKey.rtt.value]

            rtts[inner_result[MeasurementKey.source.value]] = (
                inner_result[MeasurementKey.rtt.value],
                inner_result.get(MeasurementKey.ttl.value, None))

    return rtts, second_hop_latency


if __name__ == '__main__':
    main()
