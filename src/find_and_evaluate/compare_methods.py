#!/usr/bin/env python3
"""
This module compares the database verifying methods with the rtt method
"""

import argparse
import collections
import mmap
import enum

import src.data_processing.util as util


logger = None


@enum.unique
class CompareType(enum.Enum):
    ripe_c_db_no_data = 'ripe_c_db_no_data'
    ripe_c_db_same = 'ripe_c_db_same'
    ripe_c_db_wrong = 'ripe_c_db_wrong'
    ripe_c_db_near = 'ripe_c_db_near'

    ripe_no_v_db_no_data = 'ripe_no_v_db_no_data'
    ripe_no_v_db_l = 'ripe_no_v_db_l'
    ripe_no_v_db_wrong = 'ripe_no_v_db_wrong'

    ripe_no_l_db_no_data = 'ripe_no_l_db_no_data'
    ripe_no_l_db_wrong = 'ripe_no_l_db_wrong'

    ripe_no_data_db_no_data = 'ripe_no_data_db_no_data'
    ripe_no_data_db_l = 'ripe_no_data_db_l'


def __create_parser_arguments(parser):
    parser.add_argument('db_filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string')
    parser.add_argument('ripe_filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string')
    parser.add_argument('-f', '--file-count', type=int, default=8,
                        dest='fileCount',
                        help='number of files from preprocessing')
    parser.add_argument('-loc', '--location-file-name', required=True, type=str,
                        dest='locationFile',
                        help='The path to the location file.'
                             ' The output file from the codes_parser')
    parser.add_argument('-v', '--ip-version', type=str, dest='ip_version',
                        default=util.IPV4_IDENTIFIER,
                        choices=[util.IPV4_IDENTIFIER, util.IPV6_IDENTIFIER],
                        help='specify the ipVersion')
    parser.add_argument('-l', '--logging-file', type=str, default='compare_methods.log',
                        dest='log_file',
                        help='Specify a logging file where the log should be saved')


def main():
    """Main Method"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    global logger
    logger = util.setup_logger(args.log_file, 'compare')
    logger.debug('starting')

    with open(args.locationFile) as locationFile:
        locations = util.json_load(locationFile)

    for index in range(0, args.fileCount):
        classif_domains = collections.defaultdict(list)
        database_domains = {}
        with open(args.db_filename_proto.format(index)) as database_domain_file, \
                mmap.mmap(database_domain_file.fileno(), 0) as database_domain_file_mm:
            line = database_domain_file_mm.readline().decode('utf-8')
            while len(line):
                domain_list = util.json_loads(line)
                for domain in domain_list:
                    database_domains[domain.ip_for_version(args.ip_version)] = domain
                line = database_domain_file_mm.readline().decode('utf-8')
        with open(args.ripe_filename_proto.format(index)) as ripe_domain_file, \
                mmap.mmap(ripe_domain_file.fileno(), 0) as ripe_domain_file_mm:
            line = ripe_domain_file_mm.readline().decode('utf-8')
            while len(line):
                domain_dict = util.json_loads(line)
                for ripe_domain in domain_dict[util.DomainType.correct]:
                    db_domain = database_domains[ripe_domain.domain.ip_for_version(args.ip_version)]
                    if not db_domain.location_id:
                        classif_domains[CompareType.ripe_c_db_no_data].append(
                            (db_domain, ripe_domain))
                    elif db_domain.location_id == ripe_domain.location_id:
                        classif_domains[CompareType.ripe_c_db_same].append((db_domain, ripe_domain))
                    else:
                        db_location = locations[str(db_domain.location_id)]
                        ripe_location = locations[str(ripe_domain.location_id)]
                        ripe_matching_rtt = ripe_domain.matching_match.matching_rtt
                        distance = db_location.gps_distance_equirectangular(ripe_location)
                        if distance < ripe_matching_rtt*100:
                            classif_domains[CompareType.ripe_c_db_near].append(
                                (db_domain, ripe_domain))
                        else:
                            classif_domains[CompareType.ripe_c_db_wrong].append(
                                (db_domain, ripe_domain))

                for ripe_domain in domain_dict[util.DomainType.no_verification]:
                    db_domain = database_domains[ripe_domain.domain.ip_for_version(args.ip_version)]
                    if not db_domain.location_id:
                        classif_domains[CompareType.ripe_no_v_db_no_data].append(
                            (db_domain, ripe_domain))
                    else:
                        db_match = db_domain.matching_match
                        if db_match.location_id in \
                                [match.location_id for match in ripe_domain.possible_matches]:
                            classif_domains[CompareType.ripe_no_v_db_l].append(
                                (db_domain, ripe_domain))
                        else:
                            classif_domains[CompareType.ripe_no_v_db_wrong].append(
                                (db_domain, ripe_domain))

                for ripe_domain in domain_dict[util.DomainType.no_location]:
                    db_domain = database_domains[ripe_domain.domain.ip_for_version(args.ip_version)]
                    if not db_domain.location_id:
                        classif_domains[CompareType.ripe_no_l_db_no_data].append(
                            (db_domain, ripe_domain))
                    else:
                        classif_domains[CompareType.ripe_no_l_db_wrong].append(
                            (db_domain, ripe_domain))

                for ripe_domain in domain_dict[util.DomainType.not_responding]:
                    db_domain = database_domains[ripe_domain.domain.ip_for_version(args.ip_version)]
                    if not db_domain.location_id:
                        classif_domains[CompareType.ripe_no_data_db_no_data].append(
                            (db_domain, ripe_domain))
                    else:
                        classif_domains[CompareType.ripe_no_data_db_l].append(
                            (db_domain, ripe_domain))

                line = ripe_domain_file_mm.readline().decode('utf-8')

        with open('compared-ripe-db-{}.out'.format(index), 'w') as output_file:
            for key, domain_list in classif_domains.items():
                logger.info('{} len {}\n'.format(key, len(domain_list)))
                output_file.write('{} len {}\n'.format(key, len(domain_list)))
                util.json_dump(domain_list, output_file)
                output_file.write('\n')

        classif_domains.clear()


if __name__ == '__main__':
    main()
