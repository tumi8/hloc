#!/usr/bin/env python3
"""
Parse data from the zmap result files
"""

import argparse
import configparser
import os
import re
import typing

from hloc import util
from hloc.models import Session, ZmapProbe, ZmapMeasurementResult
from hloc.db_utils import create_session_for_process, location_for_coordinates


logger = None


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('zmap_results_dir', type=str,
                        help='Path to the directory with the zmap files')
    parser.add_argument('locations_config_file', type=str,
                        help='a config file with the location keys and their GPS coordinates')
    parser.add_argument('-r', '--file-regex', type=str, default=r'.*scanned$')
    parser.add_argument('-l', '--logging-file', type=str, default='zmap-results-import.log',
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
    logger = util.setup_logger(args.logging_file, 'parse_zmap_results')

    Session = create_session_for_process()
    db_session = Session()

    filenames = get_filenames(args.zmap_results_dir, args.file_regex)
    locations = {}

    config_parser = configparser.ConfigParser()
    if os.path.isfile(args.locations_config_file):
        config_parser.read(args.locations_config_file)
        for filename in filenames:
            location_name = __get_location_name(filename)
            if location_name not in config_parser or \
                    'lat' not in config_parser[location_name] or \
                    'lon' not in config_parser[location_name]:
                logger.critical('{} not defined in config file or has not the right format! '
                                'Aborting!'.format(location_name))
                return 3

            location = location_for_coordinates(config_parser[location_name]['lat'],
                                                config_parser[location_name]['lon'], db_session)
            probe = ZmapProbe(probe_id=location_name, location=location)
            db_session.add(probe)
            db_session.commit()
            locations[location_name] = probe.id
    else:
        raise ValueError('locations_config_file path does not lead to a file')

    parse(filenames, locations, db_session)

    db_session.close()
    Session.remove()


def get_filenames(archive_path: str, file_regex: str) -> [str]:
    filenames = []
    file_regex_obj = re.compile(file_regex, flags=re.MULTILINE)

    for dirname, _, names in os.walk(archive_path):
        for filename in names:
            if file_regex_obj.match(filename):
                filenames.append(os.path.join(dirname, filename))

    return filenames


def __get_location_name(filename):
    return os.path.basename(filename).split('.')[0]


def parse(filenames: [str], location_probe_ids: typing.Dict[str, int],
          db_session: Session):
    for filename in filenames:
        location_name = __get_location_name(filename)
        probe_id = location_probe_ids[location_name]
        parse_zmap_results(filename, probe_id, db_session)


def parse_zmap_results(zmap_filepath: str, probe_id: int, db_session: Session):
    """Parses a file """
    measurements = {}
    with open(zmap_filepath) as zmap_file:
        for line in zmap_file:
            if line[0:5] == 'saddr':
                continue

            zmap_measurement = ZmapMeasurementResult.create_from_archive_line(line, probe_id)
            if zmap_measurement and (zmap_measurement.destination_address not in measurements or
                                     measurements[zmap_measurement.destination_address].rtt >
                                     zmap_measurement.rtt):
                measurements[zmap_measurement.destination_address] = zmap_measurement

    logger.info('parsed {} unique destination rtts from {}'.format(len(measurements),
                                                                   zmap_filepath))
    db_session.bulk_save_objects(measurements.values())
    db_session.commit()


if __name__ == '__main__':
    main()
