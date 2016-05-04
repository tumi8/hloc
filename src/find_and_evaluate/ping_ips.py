#!/usr/bin/env python

from __future__ import print_function
import json
import argparse
import subprocess
import sys
import codecs
from threading import Thread, Semaphore


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename_proto', type=str,
                        help=r'The path to the files with {} instead of the filenumber'
                        ' in the name so it is possible to format the string')
    parser.add_argument('-f', '--file-count', type=int, default=8, dest='fileCount',
                        help='number of files from preprocessing')
    parser.add_argument('-s', '--server-name', type=str, dest='serverName', required=True,
                        help='number of files from preprocessing')

    args = parser.parse_args()

    thread_sema = Semaphore(1000)
    threads = []
    for index in range(0, args.fileCount):
        ipresults = codecs.open('ip_results_{}.json'.format(index), 'w', encoding='utf-8')
        ipFile = codecs.open(args.filename_proto.format(index), 'r', encoding='utf-8')
        print('reading file', args.filename_proto.format(index))
        sys.stdout.flush()
        for line in ipFile:
            ips = json.loads(line)
            for ipIndex in range(0, len(ips)):
                if ips[ipIndex]['blacklisted']:
                    continue
                thread_sema.acquire()
                thread = Thread(target=measure_ping, args=(ips, ipIndex,
                                                           args.serverName, thread_sema))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            threads = []

            json.dump(ips, ipresults)
            ipresults.write('\n')
            print('wrote', len(ips), 'results')
            sys.stdout.flush()
        ipFile.close()
        ipresults.close()


def get_min_rtt(ping_output):
    """
    parses the min rtt from a ping output
    """
    if ping_output is None:
        return None
    min_rtt_str = ping_output[(ping_output.find('mdev = ') + len('mdev = ')):]
    min_rtt_str = min_rtt_str[:min_rtt_str.find('/')]
    return float(min_rtt_str)


def measure_ping(ips, index, serverName, thread_sema):
    args = ['ping', '-fnc', '4', ips[index]['ip']]
    output = None
    ips[index]['rtt'] = {}
    try:
        output = subprocess.check_output(args)
    except subprocess.CalledProcessError as error:
        if error.returncode == 1:
            ips[index]['rtt'][serverName] = None
            thread_sema.release()
            return
        print(error.output)
        raise error
    # except subprocess.TimeoutExpired:
    #     ips[index]['rtt'][serverName] = None
    #     thread_sema.release()
    #     return
    # Only for Python3
    except:
        raise
    ips[index]['rtt'][serverName] = get_min_rtt(str(output))
    thread_sema.release()


if __name__ == '__main__':
    main()
