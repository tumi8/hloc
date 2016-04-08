#!/usr/bin/env python

import json
import argparse
from multiprocessing import Process
from netaddr import IPNetwork, IPAddress


def address_in_network(ip, net):
    return IPAddress(ip) in net


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                        ' in the name so it is possible to format the string')
    parser.add_argument('-f', '--file-count', type=int, default=8, dest='fileCount',
                        help='number of files from preprocessing')
    parser.add_argument('blacklist', type=str,
                        help='The path to the ip blacklist')

    args = parser.parse_args()

    blacklist_networks = []
    with open(args.blacklist, 'r') as blacklistFile:
        for line in blacklistFile:
            if len(line) > 0:
                blacklist_networks.append(IPNetwork(line[:-1]))

    processes = []
    for pid in range(0, args.fileCount):
        process = Process(target=get_ips, args=(args.filename_proto.format(pid),
                                                pid, blacklist_networks))
        processes.append(process)
        process.start()
        if len(processes) == 4:
            processes[0].join()
            processes[1].join()
            processes[2].join()
            processes[3].join()
            processes = []


def get_ips(filename, pid, blacklist_networks):
    ip_file = open(filename, 'r', encoding='utf-8')
    ip_w_file = open('ips_{}.json'.format(pid), 'w', encoding='utf-8')
    print('started', pid, 'for filename', filename)

    def address_in_blacklist(ip):
        for net in blacklist_networks:
            if address_in_network(ip, net):
                return True

        return False

    for line in ip_file:
        entries = json.loads(line)
        print('pid', pid, 'len', len(entries))
        ips = []
        for entry in entries:
            ips.append({'ip': entry['ip'], 'blacklisted': address_in_blacklist(entry['ip'])})
            if len(ips) == 10**3:
                json.dump(ips, ip_w_file)
                ip_w_file.write('\n')
                print('pid', pid, 'wrote', len(ips))
                ips = []
        json.dump(ips, ip_w_file)
        ip_w_file.write('\n')
        print('pid', pid, 'wrote', len(ips))
    ip_w_file.close()
    ip_file.close()


if __name__ == '__main__':
    main()
