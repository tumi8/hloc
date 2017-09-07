#!/usr/bin/env python3
"""
Parse Caida icmp ping data
"""

import argparse
import bz2
import datetime
import mmap
import multiprocessing as mp
import os
import queue
import re
import sys
import typing

from hloc import util
from hloc.db_utils import create_session_for_process, location_for_coordinates
from hloc.models import Session, CaidaArkProbe, CaidaArkMeasurementResult


probe_lock = mp.Lock()
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

    filenames = get_filenames(args.archive_path, args.file_regex)

    processes = []

    for i in range(args.number_processes):
        process = mp.Process(target=parse_caida_data, args=(filenames, not args.plaintext,
                                                            args.days_in_past, args.debug),
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

            probe_for_id(probe_id, probe_location_dct[probe_id][0],
                         probe_location_dct[probe_id][1], db_session)

            modification_time = datetime.datetime.fromtimestamp(os.path.getmtime(filename))

            if abs((modification_time - datetime.datetime.now()).days) >= days_in_past:
                continue

            if bz2_compressed:
                with bz2.open(filename, 'rt') as caida_archive_file:
                    for line in caida_archive_file:
                        parse_measurement(line, probe_id, db_session, days_in_past)
            else:
                with open(filename) as caida_archive_filedesc, \
                        mmap.mmap(caida_archive_filedesc.fileno(), 0,
                                  access=mmap.ACCESS_READ) as caida_archive_file:
                    line = caida_archive_file.readline().decode('utf-8')

                    while len(line) > 0:
                        parse_measurement(line, probe_id, db_session, days_in_past)

                        line = caida_archive_file.readline().decode('utf-8')

            if debugging:
                break

    except queue.Empty:
        pass

    db_session.commit()


def probe_for_id(probe_id: str, lat: float, lon: float, db_session: Session):
    with probe_lock:
        probe_obj = db_session.query(CaidaArkProbe).filter_by(probe_id=probe_id).first()
        if probe_obj:
            return

        location = location_for_coordinates(lat, lon, db_session)

        probe_obj = CaidaArkProbe(location=location, probe_id=probe_id)
        db_session.add(probe_obj)
        db_session.commit()


def parse_measurement(archive_line: str, probe_id: str, db_session: Session, days_in_past: int):
    if archive_line.startswith('timestamp'):
        return

    measurement = CaidaArkMeasurementResult.create_from_archive_line(archive_line, probe_id)

    if (datetime.datetime.now() - measurement.timestamp).days < days_in_past:
        db_session.add(measurement)
