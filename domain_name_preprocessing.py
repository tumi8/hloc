#!/usr/bin/env python3

import re
import argparse
import string
import mmap
import os
import collections
import binascii
import socket

ACCEPTED_CHARACTER = frozenset('{0}.-_'.format(string.printable[0:62]))


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('filename', help='filename to sanitize', type=str)
    parser.add_argument('-e', '--encoding', default='uft-8', type=str, help='the encoding for the '
                                                                            'filename')
    parser.add_argument('-t', '--tlds-file', type=str, required=True,
                        dest='tlds_file', help='The path to the ICANN tlds file')
    parser.add_argument('-s', '--strategy', type=str, dest='regexStrategy',
                        choices=['strict', 'abstract', 'moderate'],
                        default='abstract', help='Specify a regex Strategy')
    parser.add_argument('-d', '--destination', type=str, dest='destination', default='domain-files',
                        help='the desination directory (must not exist)')
    parser.add_argument('-i', '--ip-encoding-filter', action='store_true', dest='isp_ip_filter',
                        help='set if you want to filter isp ip domain names')
    parser.add_argument('-v', '--ip-version', type=str, dest='ip_version', choices=['ipv4', 'ipv6'],
                        default='ipv4', help='specify the ipVersion')
    parser.add_argument('-f', '--white-list-file', type=str, dest='white_list_file_path',
                        help='path to a file with a white list of IPs')


def select_ip_regex(regex_strategy):
    """Selects the regular expression according to the option set in the arguments"""
    if regex_strategy == 'abstract':
        # most abstract regex
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),' \
               r'.*(\1.*\2.*\3.*\4|\4.*\3.*\2.*\1).*$'
    elif regex_strategy == 'moderate':
        # slightly stricter regex
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),' \
               r'.*(\1.+\2.+\3.+\4|\4.+\3.+\2.+\1).*$'
    elif regex_strategy == 'strict':
        # regex with delimiters restricted to '.','-' and '_'
        return r'^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}),' \
               r'.*(0{0,2}?\1[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\3[\.\-_]' \
               r'0{0,2}?\4|0{0,2}?\4[\.\-_]0{0,2}?\3[\.\-_]0{0,2}?\2[\.\-_]0{0,2}?\1).*$'


def main():
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()
    ipregex_text = select_ip_regex(args.regexStrategy)
    ipregex = re.compile(ipregex_text, flags=re.MULTILINE)

    tlds = set()
    with open(args.tlds_file) as tldFile:
        for line in tldFile:
            line = line.strip()
            if line[0] != '#':
                tlds.add(line.lower())

    white_list = None
    if args.white_list_file_path:
        white_list = set()
        with open(args.white_list_file_path) as filter_list_file:
            for line in filter_list_file:
                white_list.add(line.strip())

    os.mkdir(args.destination)

    ip_domain_tuples = []

    filename = args.filename
    with open(filename, encoding=args.encoding) as domain_file, \
            mmap.mmap(domain_file.fileno(), 0, access=mmap.ACCESS_READ) as domain_file_mm, \
            open(os.path.join(args.destination, filename), 'w', encoding='utf-8') as correct_file, \
            open(os.path.join(args.destination, filename), 'w', encoding='utf-8') as \
            ip_encoded_file, \
            open(os.path.join(args.destination, filename), 'w', encoding='utf-8') as bad_file, \
            open(os.path.join(args.destination, filename), 'w', encoding='utf-8') as bad_dns_file, \
            open(os.path.join(args.destination, filename), 'w', encoding='utf-8') as \
            custom_filter_file:

        def save(correct, bad, bad_dns, ip_encoded, custom_filtered):
            correct_file.write('\n'.join([','.join(tup) for tup in correct]) + '\n')
            bad_file.write('\n'.join([','.join(tup) for tup in bad]) + '\n')
            bad_dns_file.write('\n'.join([','.join(tup) for tup in bad_dns]) + '\n')
            ip_encoded_file.write('\n'.join([','.join(tup) for tup in ip_encoded]) + '\n')
            custom_filter_file.write('\n'.join([','.join(tup) for tup in custom_filtered]) + '\n')

        line = domain_file_mm.readline().decode(args.encoding)
        while line:
            line = line.strip()
            ip_domain_tuples.append(line.split(',', 1))

            if len(ip_domain_tuples) > 10**5:
                correct, bad, bad_dns, ip_encoded, custom_filtered, _ = preprocess_domains(
                    ip_domain_tuples, ipregex, tlds, white_list=white_list,
                    ip_version=args.ip_version)
                save(correct, bad, bad_dns, ip_encoded, custom_filtered)
                del ip_domain_tuples[:]

            line = domain_file_mm.readline().decode(args.encoding)

        correct, bad, bad_dns, ip_encoded, custom_filtered, _ = preprocess_domains(
            ip_domain_tuples, ipregex, tlds, white_list=white_list)
        save(correct, bad, bad_dns, ip_encoded, custom_filtered)


def preprocess_domains(ip_domain_tuples: [(str, str)], ipregex: re, tlds: {str},
                       white_list: {str} = None, ip_version: str = 'ipv4',
                       ip_encoding_filter: bool = True):
    """
    Sanitize filepart from start to end
    pnr is a number to recognize the process
    ipregex should be a regex with 4 integers to filter the Isp client domain names
    """

    bad_characters = collections.defaultdict(int)
    bad_lines = []
    good_lines = []
    bad_dns_lines = []
    ip_encoded_lines = []
    custom_filter_lines = []

    is_ipv6 = ip_version == 'ipv6'

    for ip_address, domain in ip_domain_tuples:

        if set(domain).difference(ACCEPTED_CHARACTER):
            bad_lines.append((ip_address, domain))
        else:
            if white_list is not None and ip_address not in white_list:
                custom_filter_lines.append((ip_address, domain))
            elif not is_ipv6 and ip_encoding_filter and has_ip_encoded(ip_address, domain, ipregex):
                ip_encoded_lines.append((ip_address, domain))
            elif not is_ipv6 and ip_encoding_filter and \
                    is_ip_hex_encoded(ip_address, domain):
                ip_encoded_lines.append((ip_address, domain))
            elif ip_encoding_filter and has_ip_alphanumeric_encoded(ip_address, domain, ip_version):
                ip_encoded_lines.append((ip_address, domain))
            else:
                if domain.split('.')[-1] in tlds:
                    good_lines.append((ip_address, domain))
                else:
                    bad_dns_lines.append((ip_address, domain))

    return good_lines, bad_lines, bad_dns_lines, ip_encoded_lines, custom_filter_lines, \
        bad_characters


def hex_for_ip(ip_address):
    """Returns the hexadecimal code for the ip address"""
    ip_blocks = [int(ip_block) for ip_block in ip_address.split('.')]
    hexdata = '{:02X}{:02X}{:02X}{:02X}'.format(*ip_blocks)
    return hexdata


def is_ip_hex_encoded(ip_address, domain):
    """check if the ip address is encoded in hex format in the domain"""
    hex_ip = hex_for_ip(ip_address)

    return hex_ip.upper() in domain.upper()


def has_ip_encoded(ip, domain, ipregex):
    """Basic check if the domain is a isp client domain address"""
    return ipregex.search(ip + ',' + domain)


def ip_to_int(ip_addr, ip_version):
    if ip_version == 'ipv6':
        return int(binascii.hexlify(socket.inet_pton(socket.AF_INET6, ip_addr)), 16)
    elif ip_version == 'ipv4':
        return int(binascii.hexlify(socket.inet_pton(socket.AF_INET, ip_addr)), 16)


def has_ip_alphanumeric_encoded(ip_address, domain, ip_version):
    return int_to_alphanumeric(ip_to_int(ip_address, ip_version)) in domain


def int_to_alphanumeric(num: int):
    rest = num % 36
    if rest < 10:
        rest_ret = '{}'.format(rest)
    else:
        rest_ret = '{}'.format(chr(ord('a')+rest-10))
    div = num // 36
    if div == 0:
        return rest_ret
    else:
        return int_to_alphanumeric(div) + rest_ret

if __name__ == '__main__':
    main()

__all__ = [has_ip_encoded, is_ip_hex_encoded, preprocess_domains]
