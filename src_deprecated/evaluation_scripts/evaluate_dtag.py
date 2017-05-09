#!/usr/bin/env python

import argparse
import socket
import struct
import collections

import src_deprecated.data_processing.util as util

logger = None


def __create_parser_arguments(parser):
    parser.add_argument('dtag_file', type=str,
                        help=r'The path to the dtag ground truth file')
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
    parser.add_argument('-o', '--output-file', type=str, default='dtag_output.domains',
                        dest='output_file',
                        help='Specify a output file where the dtag domains should be saved')

    parser.add_argument('-l', '--logging-file', type=str, default='compare_methods.log',
                        dest='log_file',
                        help='Specify a logging file where the log should be saved')


def main():
    """Main Method"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    global logger
    logger = util.setup_logger(args.log_file, 'dtag_eval')
    logger.debug('starting')

    dtag_ip_to_location = parse_dtag_file(args.dtag_file)
    dtag_ip_to_range = dtag_ips_to_range(dtag_ip_to_location)

    dtag_ip_count = 0
    dtag_type_count = collections.defaultdict(int)
    dtag_domain_dict = collections.defaultdict(dict)

    for i in range(0, args.fileCount):
        with open(args.ripe_filename_proto.format(i)) as ripe_file:
            for line in ripe_file:
                domain_type_dict = util.json_loads(line)
                for type, domains in domain_type_dict:
                    for domain in domains:
                        if domain.ip_address in dtag_ip_to_range:
                            dtag_ip_count += 1
                            dtag_type_count[type] += 1

                            dtag_range = dtag_ip_to_range[domain.ip_address]

                            if type not in dtag_domain_dict[dtag_range]:
                                dtag_domain_dict[dtag_range][type] = []

                            dtag_domain_dict[dtag_range][type].append(domain)

    with open(args.output_file, 'w') as output_file:
        util.json_dump(dtag_domain_dict, output_file)

    logger.info('Collected {} dtag domains\nCorrect: {}, unknown: {}, no_location: {}, not_responding: {}'.format(
        dtag_ip_count,
        dtag_type_count[util.DomainType.correct.value],
        dtag_type_count[util.DomainType.no_verification.value],
        dtag_type_count[util.DomainType.no_location.value],
        dtag_type_count[util.DomainType.not_responding.value]))


def parse_dtag_file(filepath):
    dtag_ip_to_location = {}
    with open(filepath) as dtag_file:
        for line in dtag_file:
            line = line.strip()
            _, ip_range, _, lat, lon = line.split('\t')
            dtag_ip_to_location[ip_range] = {'lat': lat, 'lon': lon}

    return dtag_ip_to_location

def dtag_ips_to_range(dtag_ip_to_location):
    dtag_ip_to_range = {}
    for ip_range in dtag_ip_to_location.keys():
        base_ip, subnet_bits = ip_range.split('/')
        base_ip_int = struct.unpack('>I', socket.inet_aton(base_ip))[0]

        ips = [socket.inet_ntoa(struct.pack('>I', i)) for i in range(base_ip_int, base_ip_int + (2**subnet_bits))]

        for ip in ips:
            dtag_ip_to_range[ip] = ip_range

    return dtag_ip_to_range

