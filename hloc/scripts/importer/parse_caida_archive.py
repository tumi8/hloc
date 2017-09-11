#!/usr/bin/env python3
"""
Parse Caida icmp ping data
"""

import argparse
import bz2
import datetime
import json
import mmap
import multiprocessing as mp
import os
import queue
import re
import sys
import threading
import typing

import sqlalchemy.exc as sqla_exceptions

from hloc import util
from hloc.db_utils import create_session_for_process, location_for_coordinates, \
    location_for_iata_code
from hloc.models import Session, CaidaArkProbe, CaidaArkMeasurementResult


probe_lock = mp.Lock()
logger = None


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('archive_path', type=str,
                        help='Path to the directory with the archive files')
    parser.add_argument('caida_locations_path', type=str,
                        help='Path to the JSON file with the Caida probe names')
    parser.add_argument('-p', '--number-processes', type=int, default=4,
                        help='specify the number of processes used')
    parser.add_argument('-r', '--file-regex', type=str, default=r'(ping|traceroute).*\.bz2$')
    parser.add_argument('-t', '--plaintext', action='store_true', help='Use plaintext filereading')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-h', '--days-in-past', type=int, default=30,
                        help='The number of days in the past for which parsing will be done')
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
    logger = util.setup_logger(args.logging_file, 'parse_ripe_archive')

    if not os.path.isdir(args.archive_path):
        print('Archive path does not lead to a directory', file=sys.stderr)
        return 1

    if not os.path.isfile(args.caida_locations_path):
        print('Caida probe locations file not found', file=sys.stderr)
        return 1

    filenames = get_filenames(args.archive_path, args.file_regex)

    with open(args.caida_locations_path) as caida_probe_locations:
        probe_names_list = json.load(caida_probe_locations)

    Session = create_session_for_process()
    db_session = Session()
    probe_locations_dct = {}

    for probe_id in probe_names_list:
        probe = pr
        location = location_for_iata_code(probe_id[:3], db_session)
        if location:
            probe_locations_dct[probe_id] = location.id
        else:
            logger.warning('couldn\'t find location for probe id {}'.format(probe_id))


    processes = []

    for i in range(args.number_processes):
        process = mp.Process(target=parse_caida_data, args=(filenames, not args.plaintext,
                                                            args.days_in_past, args.debug,
                                                            probe_locations_dct),
                             name='parse caida data {}'.format(i))
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


def read_bz2_file_queued(line_queue: queue.Queue, filename: str, finished_reading: threading.Event):
    with bz2.open(filename, 'rt') as ripe_archive_file:
        for line in ripe_archive_file:
            line_queue.put(line)

    finished_reading.set()


def parse_caida_probe(probe_id: str, probe_location_dct: typing.Dict[str, typing.List[float]],
                      db_session: Session) \
        -> typing.Optional[CaidaArkProbe]:
    caida_probe = db_session.query(CaidaArkProbe).filter_by(probe_id=probe_id).first()
    if caida_probe:
        return caida_probe

    with probe_lock:
        caida_probe = db_session.query(CaidaArkProbe).filter_by(probe_id=probe_id).first()
        if caida_probe:
            return caida_probe

        if probe_id not in probe_location_dct:
            logger.debug('could not write measurement because probe ({}) has no location'.format(
                probe_id))
            return None

        caida_probe = CaidaArkProbe(probe_id=probe_id, location_id=probe_location_dct)
        db_session.add(caida_probe)
        db_session.commit()
        return caida_probe


def parse_caida_data(filenames: mp.Queue, bz2_compressed: bool, days_in_past: int, debugging: bool,
                     probe_location_dct: typing.Dict[str, typing.List[float]]):
    Session = create_session_for_process()
    db_session = Session()
    try:
        while True:
            filename = filenames.get(timeout=1)

            probe_id = filename.split('.')[0]

            if probe_id not in probe_location_dct:
                ValueError('location dict does not contain location for Probe with key {}'.format(
                    probe_id))

            probe = parse_caida_probe(probe_id, probe_location_dct, db_session)

            modification_time = datetime.datetime.fromtimestamp(os.path.getmtime(filename))

            if abs((modification_time - datetime.datetime.now()).days) >= days_in_past:
                continue

            if bz2_compressed:
                line_queue = queue.Queue(10 ** 5)
                finished_reading = threading.Event()
                read_thread = threading.Thread(target=read_bz2_file_queued,
                                               args=(line_queue, filename, finished_reading),
                                               name='bz2 read thread')
                read_thread.start()

                def line_generator():
                    try:
                        rline = line_queue.get(2)
                    except queue.Empty:
                        return
                    while True:
                        yield rline
                        if finished_reading.is_set() and line_queue.empty():
                            return
                        rline = line_queue.get()

                for line in line_generator():
                    parse_measurement(line, probe, db_session, days_in_past)
            else:
                with open(filename) as caida_archive_filedesc, \
                        mmap.mmap(caida_archive_filedesc.fileno(), 0,
                                  access=mmap.ACCESS_READ) as caida_archive_file:
                    line = caida_archive_file.readline().decode('utf-8')

                    while len(line) > 0:
                        parse_measurement(line, probe, db_session, days_in_past)

                        line = caida_archive_file.readline().decode('utf-8')

            if debugging:
                break

    except queue.Empty:
        pass

    db_session.commit()


def parse_measurement(archive_line: str, probe: CaidaArkProbe, db_session: Session, days_in_past: int):
    if archive_line.startswith('timestamp'):
        return

    measurement = CaidaArkMeasurementResult.create_from_archive_line(archive_line, probe.id)

    if (datetime.datetime.now() - measurement.timestamp).days < days_in_past:
        db_session.add(measurement)
