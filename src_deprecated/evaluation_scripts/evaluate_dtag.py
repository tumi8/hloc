#!/usr/bin/env python

import argparse
import socket
import struct
import collections
import mmap

import src_deprecated.data_processing.util as util

logger = None

# 16371534 dtag ips

def __create_parser_arguments(parser):
    parser.add_argument('dtag_file', type=str,
                        help=r'The path to the dtag ground truth file')
    parser.add_argument('ripe_woip__filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string '
                             '(without ip encoded)')
    parser.add_argument('ripe_wip__filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                             ' in the name so it is possible to format the string '
                             '(with ip encoded)')
    parser.add_argument('-f', '--file-count', type=int, default=8,
                        dest='fileCount',
                        help='number of files from preprocessing')
    # parser.add_argument('-loc', '--location-file-name', required=True, type=str,
    #                     dest='locationFile',
    #                     help='The path to the location file.'
    #                          ' The output file from the codes_parser')
    parser.add_argument('-o', '--output-file', type=str, default='dtag_output.domains',
                        dest='output_file',
                        help='Specify a output file where the dtag domains should be saved')

    parser.add_argument('-l', '--logging-file', type=str, default='eval_dtag.log',
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

    dtag_ip_count += parse_ripe_domains(args.ripe_woip__filename_proto, args.fileCount,
                                        dtag_ip_to_range, dtag_type_count, dtag_domain_dict)
    dtag_ip_count += parse_ripe_domains(args.ripe_wip__filename_proto, args.fileCount,
                                        dtag_ip_to_range, dtag_type_count, dtag_domain_dict)

    with open(args.output_file, 'w') as output_file:
        util.json_dump(dtag_domain_dict, output_file)

    logger.info('Collected {} dtag domains\nCorrect: {}, unknown: {}, no_location: {}, '
                'not_responding: {}'.format(
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
        ips = [socket.inet_ntoa(struct.pack('>I', i)) for i in range(base_ip_int, base_ip_int +
                                                                     (2**(32-int(subnet_bits))))]

        for ip in ips:
            dtag_ip_to_range[ip] = ip_range

    return dtag_ip_to_range


def parse_ripe_domains(filename_proto, file_count, dtag_ip_to_range, dtag_type_count,
                       dtag_domain_dict):
    count = 0
    for i in range(0, file_count):
        with open(filename_proto.format(i)) as ripe_file_ptr, \
                mmap.mmap(ripe_file_ptr.fileno(), 0, access=mmap.ACCESS_READ) as ripe_file:
            line = ripe_file.readline().decode('utf-8')
            while line:
                domain_type_dict = util.json_loads(line)
                for domain_type, domains in domain_type_dict.items():
                    for domain in domains:
                        if domain.ip_address in dtag_ip_to_range:
                            count += 1
                            dtag_type_count[domain_type] += 1

                            dtag_range = dtag_ip_to_range[domain.ip_address]

                            if domain_type not in dtag_domain_dict[dtag_range]:
                                dtag_domain_dict[dtag_range][domain_type] = []

                            dtag_domain_dict[dtag_range][domain_type].append(domain)

                line = ripe_file.readline().decode('utf-8')

    return count

if __name__ == '__main__':
    main()
