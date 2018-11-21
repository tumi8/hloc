#!/usr/bin/env python3
"""Some utility functions"""

import binascii
import inspect
import logging
import logging.handlers
import os
import socket
import subprocess
import ipaddress
import cProfile
import multiprocessing_logging
import time
import multiprocessing as mp
import threading

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


def setup_logger(filename: str, loggername: str, loglevel: str='DEBUG', hourly_log_rotation: bool=False) -> logging.Logger:
    """does the basic config on logging"""
    # TODO only make basic setup and each script should get its logger on its own
    numeric_level = getattr(logging, loglevel.upper(), None)

    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: {}'.format(loglevel))

    if hourly_log_rotation:
        file_rotation_handler = logging.handlers.TimedRotatingFileHandler(filename)
    else:
        file_rotation_handler = logging.handlers.TimedRotatingFileHandler(filename, when='midnight')

    logging.basicConfig(level=numeric_level,
                        format=u'[%(asctime)s][%(name)-{}s][%(levelname)-s][%(processName)s][%(threadName)s] '
                               u'%(filename)s:%(lineno)d %(message)s'.format(len(loggername)),
                        datefmt='%d.%m %H:%M:%S', handlers=[file_rotation_handler])

    multiprocessing_logging.install_mp_handler()

    logging.getLogger("requests").setLevel(logging.ERROR)
    logging.getLogger("urllib3").setLevel(logging.ERROR)

    return logging.getLogger(loggername)


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


def is_ipv6_address_encoded(ipv6_address, domain):
    ip_address_exploded = ipaddress.ip_address(ipv6_address).exploded.split(':')
    return '.'.join(ip_address_exploded) in domain or '.'.join(ip_address_exploded[::-1])


def get_class_properties(subj_class) -> [str]:
    properties = inspect.getmembers(subj_class, lambda a: not (inspect.isroutine(a)))
    return [prop for (prop, _) in properties if not (prop.startswith('__') and prop.endswith('__'))]


def cprofile(file_name):
    def cprofile_decorator(func):
        def profiled_func(*args, **kwargs):
            profile = cProfile.Profile()
            try:
                profile.enable()
                result = func(*args, **kwargs)
                profile.disable()
                return result
            finally:
                profile.dump_stats(file_name)
        return profiled_func
    return cprofile_decorator


def start_token_generating_thread(sema: mp.Semaphore,
                                  tokens_per_second: int,
                                  stop_event: threading.Event) -> threading.Thread:
    generator_thread = threading.Thread(target=_start_token_generation,
                                        args=(sema, tokens_per_second, stop_event))
    generator_thread.start()

    return generator_thread


def _start_token_generation(sema: mp.Semaphore, tokens_per_second: int, stop_event: threading.Event):
    """
    Releases number of tokens_per_second tokens per second on the Semaphore
    """
    logging.debug('token generation thread started')
    while not stop_event.is_set():
        time.sleep(2 / tokens_per_second)
        try:
            sema.release()
            sema.release()
        except ValueError:
            continue
    logging.debug('token generation thread stoopped')


__all__ = ['count_lines',
           'seek_lines',
           'hex_for_ip',
           'is_ip_hex_encoded_simple',
           'get_path_filename',
           'remove_file_ending',
           'setup_logger',
           'ip_to_int',
           'int_to_alphanumeric',
           'get_class_properties']
