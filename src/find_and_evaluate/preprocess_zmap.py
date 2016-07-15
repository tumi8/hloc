#!/usr/bin/env python3
"""
This module preprocesses the zmap data for the checking module
"""

import configparser
import argparse
import os
import sys
import src.data_processing.util as util
import logging


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('dirname', help='the directory with the zmap results', type=str)
    parser.add_argument('-c', '--config-file', type=str, dest='config_filename', required=True,
                        help='The config file')
    parser.add_argument('-o', '--output-file', type=str, default='zmap.results', dest='output_file',
                        help='The output file path')
    parser.add_argument('-l', '--logging-file', type=str, default='preprocess_zmap.log',
                        dest='log_file',
                        help='Specify a logging file where the log should be saved')


def main():
    """Main"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    util.setup_logging(args.log_file)

    if not os.path.exists(args.dirname):
        print('directory does not exist!', file=sys.stderr)
        return 1

    filenames = os.walk(args.dirname).__next__()[2]
    locations = {}
    results = {}

    config_parser = configparser.ConfigParser()
    if os.path.isfile(args.config_filename):
        config_parser.read(args.config_filename)
        for filename in filenames:
            location_name = __get_location_name(filename)
            if (location_name not in config_parser  or
                    'lat' not in config_parser[location_name] or
                    'lon' not in config_parser[location_name]):
                logging.critical('{} not defined in config file or has not the right format! '
                                 'Aborting!'.format(location_name))
                return 3

            locations[location_name] = util.GPSLocation(
                config_parser[location_name]['lat'], config_parser[location_name]['lon'])
    else:
        logging.critical('Config file does not exist!')
        return 2

    logging.info('parsing')

    for filename in filenames:
        location_name = __get_location_name(filename)
        results = util.parse_zmap_results(os.path.join(args.dirname, filename), location_name, results)

    with open(args.output_file, 'w') as output_file:
        util.json_dump(locations, output_file)
        output_file.write('\n')
        util.json_dump(results, output_file)

    logging.info('finished')


def __get_location_name(filename):
    return filename.split('.')[0]

if __name__ == '__main__':
    main()
