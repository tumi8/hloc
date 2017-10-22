#!/usr/bin/env python3
"""
Delete measurements from database
"""

import argparse
import datetime

from hloc import util
from hloc.models import MeasurementResult
from hloc.db_utils import create_engine, create_session_for_process


logger = None
engine = None


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('--days-in-past', type=int, default=90,
                        help='The number of days in the past for which measurements will not be deleted')
    parser.add_argument('-dbn', '--database-name', type=str, default='hloc-measurements')
    parser.add_argument('-l', '--logging-file', type=str, default='delete-measurements.log',
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
    logger = util.setup_logger(args.logging_file, 'delete_measurements', args.log_level)

    global engine
    engine = create_engine(args.database_name)

    Session = create_session_for_process(engine)
    db_session = Session()

    oldest_date_allowed = datetime.date.today() - datetime.timedelta(days=args.days_in_past)
    db_session.query(MeasurementResult).filter(MeasurementResult.timestamp < oldest_date_allowed).delete()

    logger.info('deleted all measurements before {}'.format(oldest_date_allowed.strftime('%Y%m%d')))


if __name__ == '__main__':
    main()
