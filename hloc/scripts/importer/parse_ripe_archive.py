#!/usr/bin/env python3
"""
Parse data from the ripe archive files
"""

import argparse
import os
import sys
import multiprocessing as mp
import mmap
import json
import enum
import queue
import typing
import datetime
import collections
import bz2
import re

import ripe.atlas.cousteau as ripe_atlas

from hloc.db_utils import create_session_for_process
from hloc.models import RipeMeasurementResult, RipeAtlasProbe, Location, Session, \
    MeasurementProtocol


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('archive_path', type=str,
                        help='Path to the directory with the archive files')
    parser.add_argument('-p', '--number-processes', type=int, default=4,
                        help='specify the number of processes used')
    parser.add_argument('-r', '--file-regex', type=str, default=r'[ping|traceroute].*\.bz2$')
    parser.add_argument('-t', '--plaintext', action='store_true', help='Use plaintext filereading')
    parser.add_argument('-d', '--debug', action='store_true')
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

    if os.path.isdir(args.archive_path):
        print('Archive path does not lead to a directory', file=sys.stderr)
        return 1

    filenames = get_filenames(args.archive_path, args.file_regex)

    processes = []

    for i in range(args.number_processes):
        process = mp.Process(target=parse_ripe_data, args=(filenames, args.debug,
                                                           not args.plaintext),
                             name='parse ripe data {}'.format(i))
        processes.append(process)
        process.start()

    for process in processes:
        process.join()


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
    execution_time = 'timestamp'


def parse_ripe_data(filenames: mp.Queue, bz2_compressed: bool, debugging: bool):
    Session = create_session_for_process()
    db_session = Session()
    try:
        while True:
            filename = filenames.get(timeout=1)

            if bz2_compressed:
                with bz2.open(filename, 'rt') as ripe_archive_file:
                    for line in ripe_archive_file:
                        measurement_result = json.loads(line)

                        parse_measurement(measurement_result, db_session)
            else:
                with open(filename) as ripe_archive_filedesc, \
                    mmap.mmap(ripe_archive_filedesc.fileno(), 0,
                              access=mmap.ACCESS_READ) as ripe_archive_file:
                    line = ripe_archive_file.readline().decode('utf-8')

                    while len(line) > 0:
                        measurement_result = json.loads(line)

                        parse_measurement(measurement_result, db_session)

                        line = ripe_archive_file.readline().decode('utf-8')

            if debugging:
                break

    except queue.Empty:
        pass


def parse_probe(probe: ripe_atlas.Probe, db_session: Session) -> RipeAtlasProbe:
    probe_db_obj = db_session.query(RipeAtlasProbe).filter_by(probe_id=probe.id).first()

    if probe_db_obj:
        if probe_db_obj.update():
            return probe_db_obj

    location = Location(probe.geometry['coordinates'][1], probe.geometry['coordinates'][0])

    probe_db_obj = RipeAtlasProbe(id=probe.id, location=location)
    db_session.add(probe_db_obj)
    return probe_db_obj


def parse_measurement(measurement_result: dict, db_session: Session):
    probe_id = int(measurement_result[MeasurementKey.probe_id])

    ripe_probe = ripe_atlas.Probe(id=probe_id)

    probe = parse_probe(ripe_probe, db_session)
    execution_time = datetime.datetime.fromtimestamp(
        measurement_result[MeasurementKey.execution_time])

    destination = measurement_result[MeasurementKey.destination]

    behind_nat = False

    if MeasurementKey.source in measurement_result and \
            MeasurementKey.source_alt in measurement_result:
        # TODO check if source_alt in RFC 1918
        pass

    if MeasurementKey.source in measurement_result:
        source = measurement_result[MeasurementKey.source]
    elif MeasurementKey.source_alt in measurement_result:
        source = measurement_result[MeasurementKey.source_alt]
    else:
        raise ValueError('source not found {}'.format(str(measurement_result)))

    protocol = None
    if MeasurementKey.protocol in measurement_result:
        protocol = MeasurementProtocol(measurement_result[MeasurementKey.protocol])

    measurement_id = measurement_result[MeasurementKey.measurement_id]

    if measurement_result[MeasurementKey.type] == 'ping':
        rtts = parse_ping_results(measurement_result)

        result = RipeMeasurementResult()
        result.probe = probe
        result.execution_time = execution_time
        result.destination_address = destination
        result.source_address = source
        result.behind_nat = behind_nat
        result.rtts = rtts
        result.protocol = protocol
        result.ripe_measurement_id = measurement_id

        db_session.add(result)
        db_session.commit()
    elif measurement_result[MeasurementKey.type] == 'traceroute':
        destination_rtts = parse_traceroute_results(measurement_result)
        for dest, rtt_ttl_tuples in destination_rtts.items():
            rtts = []
            ttls = []
            for rtt, ttl in rtt_ttl_tuples:
                rtts.append(rtt)
                ttls.append(ttl)

            result = RipeMeasurementResult()
            result.probe = probe
            result.execution_time = execution_time
            result.destination_address = destination
            result.source_address = source
            result.behind_nat = behind_nat
            result.rtts = rtts
            result.ttls = ttls
            result.protocol = protocol
            result.ripe_measurement_id = measurement_id

            db_session.add(result)
            db_session.commit()


def parse_ping_results(measurement_result: typing.Dict[str, typing.Any]) -> [float]:
    rtts = []
    if MeasurementKey.result in measurement_result:
        for result in measurement_result[MeasurementKey.result]:
            rtts.append(result[MeasurementKey.rtt])
    elif MeasurementKey.min_rtt in measurement_result:
        rtts.append(measurement_result[MeasurementKey.min_rtt])
    else:
        raise ValueError('No rtt found')

    return rtts


def parse_traceroute_results(measurement_result: typing.Dict[str, typing.Any]) \
        -> typing.DefaultDict[str, typing.Tuple[float, int]]:
    rtts = collections.defaultdict(list)
    if MeasurementKey.result in measurement_result:
        for result in measurement_result[MeasurementKey.result]:
            for inner_result in result[MeasurementKey.result]:
                rtts[inner_result[MeasurementKey.source]].append((inner_result[MeasurementKey.rtt],
                                                                  inner_result[MeasurementKey.ttl]))
    else:
        raise ValueError('No rtt found')

    return rtts


if __name__ == '__main__':
    main()
