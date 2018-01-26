#!/usr/bin/env python3
"""
Parse data from the ripe archive files
"""

import argparse
import collections
import datetime
import enum
import ipaddress
import mmap
import multiprocessing as mp
import os
import queue
import re
import subprocess
import sys
import threading
import time
import typing
import ujson as json

from hloc import util
from hloc.db_utils import create_session_for_process, create_engine
from hloc.models import RipeMeasurementResult, RipeAtlasProbe, MeasurementProtocol, \
    MeasurementError, MeasurementResult
from hloc.ripe_helper.history_helper import get_archive_probes

logger = None
engine = None
buffer_lines_per_process = 1000


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
    parser.add_argument('-dbn', '--database-name', type=str, default='hloc-measurements')
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

    global engine
    engine = create_engine(args.database_name)

    parsed_file_name = '{}-parsed-ripe-files.txt'.format(args.database_name)
    parsed_files = set()

    if not os.path.exists(parsed_file_name):
        logger.debug('Creating parsed files history file for database {}'.format(
            args.database_name))
    else:
        with open(parsed_file_name) as parsed_files_histoy_file:
            for line in parsed_files_histoy_file:
                parsed_files.add(line.strip())

    filenames = get_filenames(args.archive_path, args.file_regex, parsed_files)

    Session = create_session_for_process(engine)
    db_session = Session()
    probe_dct = get_archive_probes(db_session)

    for probe, _ in probe_dct.values():
        _ = probe.id
        db_session.expunge(probe)

    db_session.close()
    Session.remove()

    processes = []

    new_parsed_files = mp.Queue()
    probe_latency_queue = mp.Queue()
    finish_event = threading.Event()

    probe_latency_thread = threading.Thread(target=update_second_hop_latency,
                                            args=(probe_latency_queue, finish_event),
                                            name='update probe latency')
    probe_latency_thread.start()

    finished_reading_event = mp.Event()

    line_queue = mp.Queue(args.number_processes * buffer_lines_per_process)
    line_thread = threading.Thread(target=read_file,
                                   args=(filenames, not args.plaintext, args.days_in_past,
                                         line_queue, finished_reading_event),
                                   name='file-reader')
    line_thread.start()
    time.sleep(1)

    for i in range(args.number_processes):
        process = mp.Process(target=parse_ripe_data, args=(filenames, not args.plaintext,
                                                           args.days_in_past, args.debug,
                                                           probe_dct, new_parsed_files,
                                                           probe_latency_queue),
                             name='parse ripe data {}'.format(i))
        processes.append(process)
        process.start()

    try:
        for process in processes:
            process.join()

    finally:
        with open(parsed_file_name, 'a') as parsed_files_histoy_file:
            while not new_parsed_files.empty():
                filename = new_parsed_files.get()
                parsed_files_histoy_file.write(filename + '\n')

    finish_event.set()
    logger.debug('finish event set waiting for second hop latency thread')

    probe_latency_thread.join()


def get_filenames(archive_path: str, file_regex: str, already_parsed_files: typing.Set[str]) \
        -> [str]:
    filenames = []
    file_regex_obj = re.compile(file_regex, flags=re.MULTILINE)

    for dirname, _, filenames in os.walk(archive_path):
        for filename in filenames:
            if file_regex_obj.match(filename) and \
                    os.path.join(dirname, filename) not in already_parsed_files:
                filenames.append(os.path.join(dirname, filename))

    return filenames


def update_second_hop_latency(probe_latency_queue: mp.Queue, finish_event: threading.Event):
    Session = create_session_for_process(engine)
    db_session = Session()

    update_sql = 'UPDATE probes SET second_hop_latency = {} WHERE id = {} AND ' \
                 '(second_hop_latency IS NULL OR second_hop_latency > {});'

    probe_dct = {}

    while not finish_event.is_set() or not probe_latency_queue.empty():
        try:
            probe_id, latency = probe_latency_queue.get(timeout=1)
            if probe_dct.get(probe_id, sys.maxsize) > latency:
                probe_dct[probe_id] = latency
        except queue.Empty:
            if finish_event.is_set():
                break

    for probe_id, latency in probe_dct.items():
        db_session.execute(update_sql.format(latency, probe_id, latency))

    logger.debug("Committing updates to second hop latency")
    db_session.commit()

    db_session.close()
    Session.remove()


def read_file(files: [str], bz2_compressed: bool, days_in_past:int, line_queue: mp.Queue,
              finished_reading_event: mp.Event):
    for filepath in files:
        file_date_str = str(os.path.basename(filepath).split('.')[0][-10:])
        modification_time = datetime.datetime.strptime(file_date_str, '%Y-%m-%d')

        if abs((modification_time - datetime.datetime.now()).days) >= days_in_past:
            continue

        logger.info('start reading %s', filepath)
        if bz2_compressed:
            read_bz2_file_queued(line_queue, filepath, days_in_past)
        else:
            with open(filepath) as ripe_archive_filedesc, \
                    mmap.mmap(ripe_archive_filedesc.fileno(), 0,
                              access=mmap.ACCESS_READ) as ripe_archive_file:
                line = ripe_archive_file.readline().decode('utf-8')

                while len(line) > 0:
                    try:
                        line_queue.put(line)
                    except queue.Full:
                        time.sleep(0.5)
                        continue
                    line = ripe_archive_file.readline().decode('utf-8')
        logger.info('finished reading')

    line_queue.close()
    finished_reading_event.set()


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
def parse_ripe_data(line_queue: mp.Queue, finished_reading: mp.Event,
                    probe_dct: typing.Dict[int, RipeAtlasProbe], probe_latency_queue: mp.Queue):
    Session = create_session_for_process(engine)
    db_session = Session()

    results = collections.defaultdict(dict)
    min_rtt_results = collections.defaultdict(dict)

    def line_generator():
        try:
            rline = line_queue.get(timeout=5)
        except queue.Empty:
            logger.exception('found empty queue')
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
            except queue.Empty:
                logger.debug('failed reading')
                read_fails += 1

    def save_measurement_results(m_results: collections.defaultdict, db_session):
        measurement_results = []
        for probe_measurement_dct in m_results.values():
            measurement_results.extend(probe_measurement_dct.values())

        db_session.bulk_save_objects(measurement_results)
        logger.info('parsed and saved %s measurements', len(measurement_results))
        db_session.commit()

        m_results.clear()

    failure_counter = 0
    parsed_lines = 0

    for line in line_generator():
        parsed_lines += 1
        try:
            measurement_result_dct = json.loads(line)

            measurement_result = parse_measurement(measurement_result_dct, probe_dct,
                                                   probe_latency_queue)

            if measurement_result and \
                    ((measurement_result.probe_id not in
                      results[measurement_result.destination_address] and
                      (measurement_result.probe_id not in min_rtt_results[
                            measurement_result.destination_address] or
                       measurement_result.min_rtt < min_rtt_results[
                            measurement_result.destination_address][
                               measurement_result.probe_id])) or
                     results[measurement_result.destination_address][
                         measurement_result.probe_id].min_rtt > measurement_result.min_rtt):
                results[measurement_result.destination_address][
                    measurement_result.probe_id] = measurement_result
                min_rtt_results[measurement_result.destination_address][
                    measurement_result.probe_id] = measurement_result.min_rtt

            if len(results) >= 10**6:
                save_measurement_results(results, db_session)

        except Exception:
            failure_counter += 1
            logger.exception('Error while parsing line %s', line)

            if parsed_lines > 100 and failure_counter >= parsed_lines / 10:
                logger.critical('failure rate too high "%s" of "%s"! stopping!', failure_counter,
                                parsed_lines)
                save_measurement_results(results, db_session)
                break

    db_session.close()
    Session.remove()

    logger.info('finished parsing')


def read_bz2_file_queued(line_queue: queue.Queue, filename: str, days_in_past: int):
    oldest_date_allowed = int((datetime.datetime.now() - datetime.timedelta(days=days_in_past))
                              .timestamp())
    if 'traceroute' in filename:
        command = 'bzcat ' + filename + ' | jq -c \'. | select(.timestamp >= ' + \
                  str(oldest_date_allowed) + ' and has("dst_addr")) | {timestamp: .timestamp, ' \
                  'dst_addr: .dst_addr, from: .from, msm_id: .msm_id, type: .type, ' \
                  'result: [.result[] | select(has("result")) | {result: [.result[] | ' \
                  'select(has("rtt") and has("from") and .rtt < 30) | ' \
                  '{rtt: .rtt, ttl: .ttl, from: .from}] | group_by(.from) | ' \
                  'map(min_by(.rtt)), hop: .hop}] | map(select(.result | length > 0) | ' \
                  '{rtt: .result[0].rtt, ttl: .result[0].ttl, from: .result[0].from, hop: .hop}),' \
                  ' proto: .proto, src_addr: .src_addr, prb_id: .prb_id} | ' \
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
            while True:
                try:
                    line_queue.put(line)
                except queue.Full:
                    time.sleep(0.5)
                else:
                    break

    logger.debug('finished reading {}'.format(filename))


def parse_measurement(measurement_result: dict, probe_dct: [int, RipeAtlasProbe],
                      probe_latency_queue: mp.Queue) \
        -> typing.Optional[MeasurementResult]:
    timestamp = datetime.datetime.fromtimestamp(
        measurement_result[MeasurementKey.timestamp.value])

    probe_id = str(measurement_result[MeasurementKey.probe_id.value])

    if probe_id not in probe_dct:
        return None

    probe, is_rfc1918 = probe_dct[probe_id]

    destination = measurement_result[MeasurementKey.destination.value]

    try:
        ipaddress.ip_address(destination)
    except ValueError:
        logger.warn("could not parse destination IP '{}'".format(destination), exc_info=True)
        return

    behind_nat = False

    if MeasurementKey.source.value in measurement_result and \
            MeasurementKey.source_alt.value in measurement_result:
        behind_nat = is_rfc1918

    if MeasurementKey.source.value in measurement_result:
        source = measurement_result[MeasurementKey.source.value]
    elif MeasurementKey.source_alt.value in measurement_result:
        source = measurement_result[MeasurementKey.source_alt.value]
    else:
        raise ValueError('source not found {}'.format(str(measurement_result)))

    if not source:
        source = None

    try:
        ipaddress.ip_address(source)
    except ValueError:
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

            if second_hop_latency:
                probe_latency_queue.put((probe.id, second_hop_latency))

            if not rtt:
                result.error_msg = MeasurementError.not_reachable

            return result


def parse_traceroute_results(measurement_result: typing.Dict[str, typing.Any]) \
        -> typing.Tuple[typing.DefaultDict[str, typing.Tuple[float, int]], typing.Optional[float]]:
    rtts = collections.defaultdict(tuple)
    second_hop_latency = None

    for result in measurement_result[MeasurementKey.result.value]:
        try:
            ip_addr = ipaddress.ip_address(result[MeasurementKey.source.value])
        except ValueError as e:
            logger.warn("could not parse IP %s", result[MeasurementKey.source.value], exc_info=True)
            continue

        if ip_addr.is_private:
            continue

        if result[MeasurementKey.hop.value] >= 2 and \
                (not second_hop_latency or
                 result[MeasurementKey.rtt.value] < second_hop_latency):
            second_hop_latency = result[MeasurementKey.rtt.value]

        rtts[result[MeasurementKey.source.value]] = (result[MeasurementKey.rtt.value],
                                                     result.get(MeasurementKey.ttl.value, None))

    return rtts, second_hop_latency


if __name__ == '__main__':
    main()
