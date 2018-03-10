#!/usr/bin/env python3
"""
Parse and store RIPE Atlas probes locally for caching purposes
"""

import argparse
import json
import os
import threading

from hloc.db_utils import create_session_for_process, create_engine
from hloc.util import start_token_generating_thread, setup_logger
from hloc.ripe_helper.probe_helper import get_probes
from hloc.constants import PROBE_CACHING_PATH


log = None


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('database_name', type=str, help='name of the database')
    parser.add_argument('-r', '--ripe-requests-per-second', type=int, default=20,
                        help='specify the of requests per second to RIPE')
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

    global log
    log = setup_logger(args.logging_file, 'parse_ripe_probes')

    engine = create_engine(args.database_name)
    Session = create_session_for_process(engine)
    db_session = Session()

    ripe_sema = threading.BoundedSemaphore(50)
    stop_event = threading.Event()
    token_generator_thread = start_token_generating_thread(ripe_sema, args.ripe_requests_per_second,
                                                           stop_event)
    probes = get_probes(db_session, ripe_sema)

    stop_event.set()
    token_generator_thread.join()

    log.info('writing probes to tmp')

    os.makedirs(os.path.dirname(PROBE_CACHING_PATH), exist_ok=True)

    with open(PROBE_CACHING_PATH, 'w') as ripe_temp_file:
        probe_info_to_write = [{probe.id: is_in_nat} for probe, is_in_nat in probes.values()]
        json.dump(probe_info_to_write, ripe_temp_file)


if __name__ == '__main__':
    main()
