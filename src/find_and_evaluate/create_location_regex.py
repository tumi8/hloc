#!/usr/bin/env python

import pickle
import re
# import ujson as json
import argparse

from ..data_processing import util


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str,
                        help='The filename with the location codes')
    args = parser.parse_args()
    regexes = []
    with open(args.filename, 'r') as locationFile:
        locations = util.json_load(locationFile)

    for location in locations.values():
        reg = make_regex_from_location(location)
        if reg is not None:
            regexes.append((location['id'], reg))

    with open('.'.join(args.filename.split('.')[:-1]) + '.pickle', 'wb') as locationRegexFile:
        pickle.dump(regexes, locationRegexFile)


def make_regex_from_location(location):
    """Creates, compiles and returns it regex"""
    if location.city_name is None:
        return None
    regex_str = build_regex_string(location)
    try:
        return re.compile(regex_str, flags=re.MULTILINE)
    except:
        print(regex_str, '\n')
        raise


def build_regex_string(location):
    """creates regex text and returns it"""
    allowedChars = r'[a-zA-Z0-9\.\-_]*'
    regexes = []
    alternate_names = location.alternate_names
    alternate_names.append(max(location.city_name.split(' '), key=len))
    regexes.append('(?P<alt>' + '|'.join(alternate_names) + ')')
    if location.locode is not None:
        regexes.append('(?P<locode>' + '|'.join(location.locode.place_codes) + ')')
    if location.airport_info is not None:
        if len(location.airport_info.iata_codes) > 0:
            regexes.append('(?P<iata>' + '|'.join(location.airport_info.iata_codes) + ')')
        if len(location.airport_info.icao_codes) > 0:
            regexes.append('(?P<icao>' + '|'.join(location.airport_info.icao_codes) + ')')
        if len(location.airport_info.faa_codes) > 0:
            regexes.append('(?P<faa>' + '|'.join(location.airport_info.faa_codes) + ')')
    if len(location.clli) > 0:
        regexes.append('(?P<clli>' + '|'.join(location.clli) + ')')
    ret = allowedChars + '(' + '|'.join(regexes) + ')' + allowedChars
    # print(ret)
    return ret


if __name__ == '__main__':
    main()
