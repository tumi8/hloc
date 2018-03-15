#!/usr/bin/env python3
"""
Parse Caida icmp ping data
"""

import argparse
import bz2
import collections
import datetime
import mmap
import multiprocessing as mp
import os
import queue
import re
import sys
import threading
import typing

from hloc import util
from hloc.db_utils import create_session_for_process, location_for_iata_code, create_engine
from hloc.models import CaidaArkProbe, CaidaArkMeasurementResult, LocationInfo


probe_lock = mp.Lock()
logger = None
engine = None


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('archive_path', type=str,
                        help='Path to the directory with the archive files')
    parser.add_argument('-p', '--number-processes', type=int, default=4,
                        help='specify the number of processes used')
    parser.add_argument('-r', '--file-regex', type=str, default=r'.*\.bz2$')
    parser.add_argument('-t', '--plaintext', action='store_true', help='Use plaintext filereading')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('--days-in-past', type=int, default=30,
                        help='The number of days in the past for which parsing will be done')
    parser.add_argument('-dbn', '--database-name', type=str, default='hloc-measurements')
    parser.add_argument('-l', '--logging-file', type=str, default='caida-archive-parsing.log',
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
    logger = util.setup_logger(args.logging_file, 'parse_ripe_archive', args.log_level)

    if not os.path.isdir(args.archive_path):
        print('Archive path does not lead to a directory', file=sys.stderr)
        return 1

    global engine
    engine = create_engine(args.database_name)

    Session = create_session_for_process(engine)
    db_session = Session()

    parsed_file_name = '{}-parsed-caida-files.txt'.format(args.database_name)
    parsed_files = set()
    
    if not os.path.exists(parsed_file_name):
        logger.debug('Creating parsed files history file for database {}'.format(
            args.database_name))
    else:
        with open(parsed_file_name) as parsed_files_histoy_file:
            for line in parsed_files_histoy_file:
                parsed_files.add(line.strip())

    filenames, probe_dct = get_filenames(args.archive_path, args.file_regex, args.days_in_past,
                                         parsed_files, db_session)

    processes = []
    new_parsed_files = mp.Queue()

    for i in range(args.number_processes):
        process = mp.Process(target=parse_caida_data, args=(filenames, not args.plaintext,
                                                            args.days_in_past, args.debug,
                                                            probe_dct, new_parsed_files),
                             name='parse caida data {}'.format(i))
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


def get_filenames(archive_path: str, file_regex: str, days_in_past: int,
                  parsed_files: typing.Set[str], db_session) \
        -> typing.Tuple[mp.Queue, typing.Dict[str, int]]:
    filename_queue = mp.Queue()
    file_regex_obj = re.compile(file_regex, flags=re.MULTILINE)

    probes = set()

    for dirname, _, filenames in os.walk(archive_path):
        for filename in filenames:
            basename = os.path.basename(filename)

            if file_regex_obj.match(filename) and \
                    os.path.join(dirname, filename) not in parsed_files:
                date_str = str(basename.split('.')[4])
                date = datetime.datetime.strptime(date_str, '%Y%m%d')

                if datetime.datetime.now() - date > datetime.timedelta(days=days_in_past):
                    continue

                probe_id = str(basename.split('.')[6])

                location = location_for_iata_code(probe_id[:3], db_session)
                if not location:
                    logger.warning('couldn\'t find location for probe id {} filename {}'.format(
                        probe_id, filename))
                    continue

                probe = parse_caida_probe(probe_id, location, db_session)
                probes.add(probe)
                filename_queue.put(os.path.join(dirname, filename))

    probe_dct = {}
    for probe in probes:
        probe_dct[probe.probe_id] = probe.id

    return filename_queue, probe_dct


def read_bz2_file_queued(line_queue: queue.Queue, filename: str, finished_reading: threading.Event):
    with bz2.open(filename, 'rt') as ripe_archive_file:
        for line in ripe_archive_file:
            line_queue.put(line)

    finished_reading.set()


def parse_caida_probe(probe_id: str, location: LocationInfo, db_session) \
        -> typing.Optional[CaidaArkProbe]:
    caida_probe = db_session.query(CaidaArkProbe).filter_by(probe_id=probe_id).first()
    if caida_probe:
        return caida_probe

    caida_probe = CaidaArkProbe(probe_id=probe_id, location_id=location.id)
    db_session.add(caida_probe)
    db_session.commit()

    return caida_probe


def parse_caida_data(filenames: mp.Queue, bz2_compressed: bool, days_in_past: int, debugging: bool,
                     probe_id_dct: typing.Dict[str, int], new_parsed_files: mp.Queue):
    Session = create_session_for_process(engine)
    db_session = Session()

    try:
        while True:
            filename = filenames.get(timeout=1)

            try:
                new_parsed_files.put(filename)

                logger.debug('parsing {}'.format(filename))

                probe_id = str(os.path.basename(filename).split('.')[0])
                probe_db_id = probe_id_dct[probe_id]

                modification_time = datetime.datetime.fromtimestamp(os.path.getmtime(filename))

                measurements = collections.defaultdict(dict)

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
                        measurement = parse_measurement(line, probe_db_id, days_in_past)

                        if measurement:
                            if measurement.probe_id not in \
                                    measurements[measurement.destination_address] or \
                                    measurements[measurement.destination_address][
                                        measurement.probe_id].min_rtt > \
                                    measurement.min_rtt:
                                measurements[measurement.destination_address][measurement.probe_id] = \
                                    measurement
                else:
                    with open(filename) as caida_archive_filedesc, \
                            mmap.mmap(caida_archive_filedesc.fileno(), 0,
                                      access=mmap.ACCESS_READ) as caida_archive_file:
                        line = caida_archive_file.readline().decode('utf-8')

                        while len(line) > 0:
                            measurement = parse_measurement(line, probe_db_id, days_in_past)

                            if measurement:
                                if measurement.probe_id not in \
                                        measurements[measurement.destination_address] or \
                                        measurements[measurement.destination_address][
                                            measurement.probe_id].min_rtt > \
                                        measurement.min_rtt:
                                    measurements[measurement.destination_address][
                                        measurement.probe_id] = \
                                        measurement

                            line = caida_archive_file.readline().decode('utf-8')

                measurement_results = []
                for probe_measurement_dct in measurements.values():
                    measurement_results.extend(probe_measurement_dct.values())

                db_session.bulk_save_objects(measurement_results)
                logger.info('parsed and saved {} measurements'.format(len(measurement_results)))
                db_session.commit()

                if debugging:
                    break

            except Exception:
                logger.exception('Error while parsing file: ')

    except queue.Empty:
        pass

    db_session.commit()

    db_session.close()
    Session.remove()


def parse_measurement(archive_line: str, probe_id: int, days_in_past: int):
    if archive_line.startswith('timestamp'):
        return

    measurement = CaidaArkMeasurementResult.create_from_archive_line(archive_line, probe_id)
    measurement.rtt = measurement.rtt + 2

    if (datetime.datetime.now() - measurement.timestamp).days < days_in_past:
        return measurement


if __name__ == '__main__':
    main()
