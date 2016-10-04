#!/usr/bin/env python3
"""
This module compares the database verifying methods with the rtt method
"""

import argparse
import collections
import mmap
import enum
import os

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
    ripe_no_l_db_possible = 'ripe_no_l_db_possible'
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

    correct_matching_distances = []
    near_matching_distances = []
    wrong_matching_distances = []

    stats = collections.defaultdict(int)

    global logger
    logger = util.setup_logger(args.log_file, 'compare')
    logger.debug('starting')

    with open(args.locationFile) as locationFile:
        locations = util.json_load(locationFile)

    filepath = os.path.dirname(args.db_filename_proto)

    for index in range(0, args.fileCount):
        classif_domains = collections.defaultdict(list)
        database_domains = {}
        with open(args.db_filename_proto.format(index)) as database_domain_file, \
                mmap.mmap(database_domain_file.fileno(), 0,
                          access=mmap.ACCESS_READ) as database_domain_file_mm:
            line = database_domain_file_mm.readline().decode('utf-8')
            while len(line):
                domain_list = util.json_loads(line)
                for domain in domain_list:
                    database_domains[domain.ip_for_version(args.ip_version)] = domain
                line = database_domain_file_mm.readline().decode('utf-8')
        with open(args.ripe_filename_proto.format(index)) as ripe_domain_file, \
                mmap.mmap(ripe_domain_file.fileno(), 0,
                          access=mmap.ACCESS_READ) as ripe_domain_file_mm:
            line = ripe_domain_file_mm.readline().decode('utf-8')
            while len(line):
                domain_dict = util.json_loads(line)
                for ripe_domain in domain_dict[util.DomainType.correct.value]:
                    db_domain = database_domains[ripe_domain.ip_for_version(args.ip_version)]
                    if db_domain.location is None:
                        classif_domains[CompareType.ripe_c_db_no_data].append(
                            (db_domain, ripe_domain))
                    else:
                        ripe_location = locations[str(ripe_domain.location_id)]
                        distance = db_domain.location.gps_distance_haversine(ripe_location)
                        if db_domain.matching_match and \
                                db_domain.matching_match.location_id == ripe_domain.location_id:
                            classif_domains[CompareType.ripe_c_db_same].append(
                                (db_domain, ripe_domain))
                            correct_matching_distances.append(distance)
                        else:
                            ripe_matching_rtt = ripe_domain.matching_match.matching_rtt
                            if distance < ripe_matching_rtt*100:
                                classif_domains[CompareType.ripe_c_db_near].append(
                                    (db_domain, ripe_domain))
                                near_matching_distances.append(distance)
                            else:
                                classif_domains[CompareType.ripe_c_db_wrong].append(
                                    (db_domain, ripe_domain))
                                wrong_matching_distances.append(distance)

                for ripe_domain in domain_dict[util.DomainType.no_verification.value]:
                    db_domain = database_domains[ripe_domain.ip_for_version(args.ip_version)]
                    if db_domain.location is None:
                        classif_domains[CompareType.ripe_no_v_db_no_data].append(
                            (db_domain, ripe_domain))
                    else:
                        db_match = db_domain.matching_match
                        if not db_match:
                            if location_possible(db_domain.all_matches, ripe_domain.all_matches):
                                classif_domains[CompareType.ripe_no_v_db_l].append(
                                    (db_domain, ripe_domain))
                            else:
                                classif_domains[CompareType.ripe_no_v_db_wrong].append(
                                    (db_domain, ripe_domain))
                        elif db_match.location_id in \
                                [match.location_id for match in ripe_domain.possible_matches]:

                            classif_domains[CompareType.ripe_no_v_db_l].append(
                                (db_domain, ripe_domain))
                        else:
                            classif_domains[CompareType.ripe_no_v_db_wrong].append(
                                (db_domain, ripe_domain))

                for ripe_domain in domain_dict[util.DomainType.no_location.value]:
                    db_domain = database_domains[ripe_domain.ip_for_version(args.ip_version)]
                    if not db_domain.location:
                        classif_domains[CompareType.ripe_no_l_db_no_data].append(
                            (db_domain, ripe_domain))
                    else:
                        if location_possible(db_domain.all_matches, ripe_domain.all_matches):
                            classif_domains[CompareType.ripe_no_l_db_possible].append(
                                (db_domain, ripe_domain))
                        else:
                            classif_domains[CompareType.ripe_no_l_db_wrong].append(
                                (db_domain, ripe_domain))

                for ripe_domain in domain_dict[util.DomainType.not_responding.value]:
                    db_domain = database_domains[ripe_domain.ip_for_version(args.ip_version)]
                    if db_domain.location is None:
                        classif_domains[CompareType.ripe_no_data_db_no_data].append(
                            (db_domain, ripe_domain))
                    else:
                        classif_domains[CompareType.ripe_no_data_db_l].append(
                            (db_domain, ripe_domain))

                line = ripe_domain_file_mm.readline().decode('utf-8')

        with open(os.path.join(filepath, 'compared-ripe-db-{}.out'.format(index)),
                  'w') as output_file:
            for key, domain_list in classif_domains.items():
                stats[key] += len(domain_list)
                logger.info('{} len {}'.format(key, len(domain_list)))
                util.json_dump(domain_list, output_file)
                output_file.write('\n')

        classif_domains.clear()

    sum_stats = sum(stats.values())
    for key, value in stats.items():
        logger.info('{} len {} percent {}'.format(key, value, value/sum_stats))

    with open(os.path.join(filepath, 'compared-ripe-db-correct-distances.out'), 'w') as output_file:
        for distance in correct_matching_distances:
            output_file.write('{}\n'.format(distance))

        logger.info('correct distances avg {}'.format(
            sum(correct_matching_distances)/len(correct_matching_distances)))

    with open(os.path.join(filepath, 'compared-ripe-db-near-distances.out'), 'w') as output_file:
        for distance in near_matching_distances:
            output_file.write('{}\n'.format(distance))

        logger.info('near distances avg {}'.format(
            sum(near_matching_distances)/len(near_matching_distances)))

    with open(os.path.join(filepath, 'compared-ripe-db-wrong-distances.out'), 'w') as output_file:
        for distance in wrong_matching_distances:
            output_file.write('{}\n'.format(distance))

        logger.info('wrong distances avg {}'.format(
            sum(wrong_matching_distances)/len(wrong_matching_distances)))


def location_possible(db_matches, ripe_matches):
    """Checks if the location is possible with the given match results"""
    for db_match in db_matches:
        ripe_match = None
        for match in ripe_matches:
            if match.location_id == db_match.location_id:
                ripe_match = match
                break

        if ripe_match and ripe_match.matching_rtt:
            if db_match.matching_distance > ripe_match.matching_rtt * 100:
                return False

    return True


if __name__ == '__main__':
    main()
