#!/usr/bin/env python

import argparse
from multiprocessing import Process
from netaddr import IPNetwork, IPAddress
import src.data_processing.util as util
import os


TEMP_NAME_PROTOTYPE = 'ips_{}.temp'
logger = None


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                        ' in the name so it is possible to format the string')
    parser.add_argument('-b', '--blacklist-file', type=str, dest='blacklist',
                        help='The path to the ip blacklist')
    parser.add_argument('-w', '--whitelist-file', type=str, dest='whitelist',
                        help='Path to whitelist')
    parser.add_argument('-f', '--file-count', type=int, default=8, dest='fileCount',
                        help='number of files from preprocessing')
    parser.add_argument('-o', '--output-filename', type=str, dest='output_filename',
                        help='the name of the outputfile')
    parser.add_argument('-v', '--ip-version', type=str, dest='ip_version',
                        choices=['ipv4', 'ipv6'], help='specify the ipVersion')
    parser.add_argument('-l', '--logging-file', type=str, default='extract_ips.log', dest='log_file',
                        help='Specify a logging file where the log should be saved')

    args = parser.parse_args()

    global logger
    logger = util.setup_logger(args.log_file, 'extract')

    blacklist_networks = None
    if args.blacklist:
        blacklist_networks = []
        with open(args.blacklist) as blacklist_file:
            for line in blacklist_file:
                line = line.strip()
                if line:
                    blacklist_networks.append(IPNetwork(line))

    whitelist_networks = None
    if args.whitelist:
        whitelist_networks = []
        with open(args.whitelist) as whitelist_file:
            for line in whitelist_file:
                line = line.strip()
                if line:
                    whitelist_networks.append(IPNetwork(line))

    processes = [None] * args.fileCount
    for pid in range(0, len(processes)):
        processes[pid] = Process(target=get_ips, args=(args.filename_proto.format(pid),
                                                       pid, blacklist_networks, whitelist_networks,
                                                       args.ip_version == 'ipv4'))

    for process in processes:
        process.start()

    for process in processes:
        process.join()

    with open(args.output_filename, 'w') as output_file:
        for pid in range(0, len(processes)):
            temp_filename = "ips_{}.temp".format(pid)
            with open(temp_filename) as ip_file:
                lines = ''
                counter = 0
                for line in ip_file:
                    lines += line
                    counter += 1
                    if counter == 10**4:
                        output_file.write(lines)
                        lines = ''
                        counter = 0

                if lines:
                    output_file.write(lines)

            os.remove(temp_filename)

    logger.info('finished extracting ips')


def get_ips(filename, pid, blacklist_networks, whitelist_networks, is_ipv4):
    with open(filename) as ip_file, open(TEMP_NAME_PROTOTYPE.format(pid), 'w') as ip_w_file:
        logger.info('started')

        def address_in_network_list(ip, network_list):
            for net in network_list:
                if address_in_network(ip, net):
                    return True
            return False

        for line in ip_file:
            entries = util.json_loads(line)
            logger.info('has entries: {}'.format(len(entries)))
            ips = []

            def add_ip(entry_ip):
                nonlocal ips
                ips.append(entry_ip)
                if len(ips) == 10 ** 4:
                    ip_w_file.write('\n'.join(ips) + '\n')
                    del ips[:]

            for entry in entries:
                if is_ipv4:
                    ip_address = entry.ip_address
                else:
                    ip_address = entry.ipv6_address
                if not ip_address:
                    continue
                if blacklist_networks:
                    if address_in_network_list(ip_address, blacklist_networks):
                        continue
                if whitelist_networks:
                    if address_in_network_list(ip_address, whitelist_networks):
                        add_ip(ip_address)
                else:
                    add_ip(ip_address)

            if ips:
                ip_w_file.write('\n'.join(ips))


def address_in_network(ip, net):
    return IPAddress(ip) in net

if __name__ == '__main__':
    main()
