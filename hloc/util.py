#!/usr/bin/env python3
"""Some utility functions"""

import binascii
import inspect
import logging
import os
import socket
import subprocess

from hloc import constants


def count_lines(filename):
    """"Opens the file at filename than counts and returns the number of lines"""
    count = subprocess.check_output(['wc', '-l', filename])
    line_count = int(count.decode().split(' ')[0])

    logging.info('Linecount for file: {0}'.format(line_count))
    return line_count


def seek_lines(seeking_file, seek_until_line):
    """Read number of lines definded in the seekPoint"""
    if seek_until_line <= 0:
        return
    i = 0
    for _ in seeking_file:
        i += 1
        if i == seek_until_line:
            break


def hex_for_ip(ip_address):
    """Returns the hexadecimal code for the ip address"""
    ip_blocks = ip_address.split('.')
    hexdata = ''
    # TODO use format %02x%02x%02x%02x
    for block in ip_blocks:
        hexdata += hex(int(block))[2:].zfill(2)
    return hexdata.upper()


def is_ip_hex_encoded_simple(ip_address, domain):
    """check if the ip address is encoded in hex format in the domain"""
    hex_ip = hex_for_ip(ip_address)

    return hex_ip.upper() in domain.upper()


def get_path_filename(path: str) -> str:
    """Extracts the filename from a path string"""
    if path[-1] == '/':
        raise NameError('The path leads to a directory')

    return os.path.basename(path)


def remove_file_ending(filenamepath: str) -> str:
    """Removes the fileending of the paths file"""
    return os.path.join(os.path.dirname(filenamepath),
                        '.'.join(get_path_filename(filenamepath).split('.')[:-1]))


def setup_logger(filename: str, loggername: str, loglevel: str = 'DEBUG') -> logging.Logger:
    """does the basic config on logging"""
    numeric_level = getattr(logging, loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: {}'.format(loglevel))
    logging.basicConfig(filename=filename, level=numeric_level,
                        format=u'[%(asctime)s][%(name)-{}s][%(levelname)-s][%(processName)s] '
                               u'%(filename)s:%(lineno)d %(message)s'.format(len(loggername)),
                        datefmt='%d.%m %H:%M:%S')
    logging.getLogger("requests").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    return logging.getLogger(loggername)


def parse_zmap_results(zmap_filename: str, location_name: str, present_results: dict):
    """Parses a file """
    zmap_results = {}
    if present_results:
        zmap_results = present_results.copy()
    with open(zmap_filename) as zmap_file:
        for line in zmap_file:
            if line[0:5] == 'saddr':
                continue
            zmap_result = parse_zmap_line(line)
            if zmap_result[0] in zmap_results:
                if location_name:
                    if location_name in zmap_results[zmap_result[0]]:
                        if zmap_result[1] < zmap_results[zmap_result[0]][location_name]:
                            zmap_results[zmap_result[0]][location_name] = zmap_result[1]
                    else:
                        zmap_results[zmap_result[0]][location_name] = zmap_result[1]
                else:
                    if zmap_result[1] < zmap_results[zmap_result[0]]:
                        zmap_results[zmap_result[0]] = zmap_result[1]
            else:
                if location_name:
                    zmap_results[zmap_result[0]] = {}
                    zmap_results[zmap_result[0]][location_name] = zmap_result[1]
                else:
                    zmap_results[zmap_result[0]] = zmap_result[1]

    return zmap_results


def parse_zmap_line(zmap_line):
    """Parses one line of an zmap output"""
    rsaddr, _, _, _, _, saddr, sent_ts, sent_ts_us, rec_ts, rec_ts_us, _, _, _, _, success = \
        zmap_line.split(',')
    if success:
        sec_difference = int(rec_ts) - int(sent_ts)
        u_sec_diference = (int(rec_ts_us) - int(sent_ts_us)) / 10 ** 6
        return rsaddr, (sec_difference + u_sec_diference) * 1000


def ip_to_int(ip_addr, ip_version):
    if ip_version == constants.IPV6_IDENTIFIER:
        return int(binascii.hexlify(socket.inet_pton(socket.AF_INET6, ip_addr)), 16)
    elif ip_version == constants.IPV4_IDENTIFIER:
        return int(binascii.hexlify(socket.inet_pton(socket.AF_INET, ip_addr)), 16)


def int_to_alphanumeric(num: int):
    rest = num % 36
    if rest < 10:
        rest_ret = '{}'.format(rest)
    else:
        rest_ret = '{}'.format(chr(ord('a') + rest - 10))
    div = num // 36
    if div == 0:
        return rest_ret
    else:
        return int_to_alphanumeric(div) + rest_ret


def get_class_properties(subj_class) -> [str]:
    properties = inspect.getmembers(subj_class, lambda a: not (inspect.isroutine(a)))
    return [prop for (prop, _) in properties if not (prop.startswith('__') and prop.endswith('__'))]

__all__ = ['count_lines',
           'seek_lines',
           'hex_for_ip',
           'is_ip_hex_encoded_simple',
           'get_path_filename',
           'remove_file_ending',
           'setup_logger',
           'parse_zmap_results',
           'parse_zmap_line',
           'ip_to_int',
           'int_to_alphanumeric',
           'get_class_properties']
