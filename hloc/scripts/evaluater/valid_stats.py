#!/usr/bin/env python3
"""
Evaluates the data in the database
"""

import argparse
import collections
import datetime
import pprint
import operator

# import sqlalchemy.ext.declarative
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from hloc import util, constants

logger = None


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('-p', '--number-processes', type=int, default=4,
                        help='specify the number of processes used')
    parser.add_argument('-dbn', '--database-name', type=str, default='hloc-debugdb')
    parser.add_argument('-dbp', '--database-password', type=str, default='hloc2017')
    parser.add_argument('-dbu', '--database-username', type=str, default='hloc')
    parser.add_argument('-v', '--ip-version', type=str, default=constants.IPV4_IDENTIFIER,
                        choices=[constants.IPV4_IDENTIFIER, constants.IPV6_IDENTIFIER],
                        help='specify the ipVersion')
    parser.add_argument('-ma', '--allowed-measurement-age', type=int,
                        help='The allowed measurement age in seconds')
    parser.add_argument('-mma', '--minimum-measurement-age', type=str,
                        help='The youngest date allowed in format "%Y-%m-%d %H:%M:%S')
    parser.add_argument('-t', '--exclude-traceroute', action='store_true')
    parser.add_argument('-c', '--exclude-caida-measurements', action='store_true')
    parser.add_argument('-o', '--output-filename', type=str)
    parser.add_argument('-l', '--log-file', type=str, default='validate-stats.log',
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
    logger = util.setup_logger(args.log_file, 'validate-stats', loglevel=args.log_level)
    logger.debug('starting')

    engine = create_engine('postgresql://{}:{}@localhost/{}'.format(
        args.database_username, args.database_password, args.database_name), echo=False)
    # Base = sqlalchemy.ext.declarative.declarative_base(bind=engine)

    db_session = scoped_session(sessionmaker(autoflush=True, bind=engine))()

    if args.allowed_measurement_age:
        oldest_date_allowed = datetime.datetime.now() - datetime.timedelta(
            seconds=args.allowed_measurement_age)
        sql_args = 'TIMESTAMP \'' + oldest_date_allowed.strftime('%Y-%m-%d %H:%M:%S') + '\', '
    else:
        sql_args = 'NULL, '

    if args.minimum_measurement_age:
        sql_args += 'TIMESTAMP \'' + args.minimum_measurement_age + '\', '
    else:
        sql_args += 'NULL, '

    sql_args += str(args.exclude_traceroute) + ', ' + str(args.exclude_caida_measurements)

    slq_query = 'SELECT * from domainsWithDistanceRTTs({});'.format(sql_args)

    results = db_session.execute(slq_query)

    rtt_distances = []
    domains_count = collections.defaultdict(int)
    location_id_count = collections.defaultdict(int)
    probes_count = collections.defaultdict(int)

    for domain_id, domain_name, hint_location_id, hint_location_name, location_hint_id, \
            measurement_result_id, probe_id, distance, min_rtt in results:
        rtt_distances.append((domain_id, min_rtt, distance))
        domains_count[domain_base_name(domain_name)] += 1
        location_id_count[hint_location_id] += 1
        probes_count[probe_id] += 1

    with open(args.output_filename, 'w') as output_file:
        str_to_wrt = '\n'.join(['{}; {}; {}'.format(domain_id, rtt, dist)
                               for domain_id, rtt, dist in rtt_distances])
        output_file.write(str_to_wrt)

    print('domains count: ')
    pprint.pprint(sorted(domains_count.items(), key=operator.itemgetter(1), reverse=True))
    print('location_id_count')
    pprint.pprint(sorted(location_id_count.items(), key=operator.itemgetter(1), reverse=True))
    print('probes_count')
    pprint.pprint(sorted(probes_count.items(), key=operator.itemgetter(1), reverse=True))


def domain_base_name(domain_name):
    return '.'.join(domain_name.split('.')[-2:])

if __name__ == '__main__':
    main()
