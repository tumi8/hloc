#!/usr/bin/env python

import pickle
import re
import json
import argparse
# pickle.load pickle.dump wie json open file mit wb und rb


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', type=str,
                        help='The filename with the location codes')
    args = parser.parse_args()
    locations = None
    regexes = []
    with open(args.filename, 'r') as locationFile:
        locations = json.load(locationFile)

    for _, location in locations.items():
        reg = make_regex_from_location(location)
        if reg is not None:
            regexes.append((location['id'], reg))

    with open('.'.join(args.filename.split('.')[:-1]) + '.pickle', 'wb') as locationRegexFile:
        pickle.dump(regexes, locationRegexFile)


def make_regex_from_location(location):
    """Creates, compiles and returns it regex"""
    if location['cityName'] is None:
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
    alternate_names = location['alternateNames']
    alternate_names.append(max(location['cityName'].split(' '), key=len))
    regexes.append('(?P<alt>' + '|'.join(alternate_names) + ')')
    if location['locode'] is not None:
        regexes.append('(?P<locode>' + '|'.join(location['locode']['placeCodes']) + ')')
    if location['airportInfo'] is not None:
        if len(location['airportInfo']['iataCode']) > 0:
            regexes.append('(?P<iata>' + '|'.join(location['airportInfo']['iataCode']) + ')')
        if len(location['airportInfo']['icaoCode']) > 0:
            regexes.append('(?P<icao>' + '|'.join(location['airportInfo']['icaoCode']) + ')')
        if len(location['airportInfo']['faaCode']) > 0:
            regexes.append('(?P<faa>' + '|'.join(location['airportInfo']['faaCode']) + ')')
    if len(location['clli']) > 0:
        regexes.append('(?P<clli>' + '|'.join(location['clli']) + ')')
    ret = allowedChars + '(' + '|'.join(regexes) + ')' + allowedChars
    # print(ret)
    return ret


if __name__ == '__main__':
    main()
