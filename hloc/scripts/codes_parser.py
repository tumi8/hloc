#!/usr/bin/env python3
"""

* Scrapes airport codes (IATA, ICAO, FAA) from world-airport-codes.com
* Parses UN/LOCODE codes from files in 1_preprocessing/data/locode*json
* Parses CLLI codes from a tab-separated CSV file (CLLI code, lat, lon)
    * this file is not included for copyright reasons
* Parses geonames from file 1_preprocessing/geonames.txt
    * You can obtain a recent copy from geonames.org
* Filters location for minimum population
* Merges locations from various sources

"""
import argparse
import json
import time
import hashlib
from string import ascii_lowercase
from string import printable
from time import sleep

import requests
from html.parser import HTMLParser

from hloc.models import LocationInfo, State, Session
from hloc.util import setup_logger
from hloc.constants import ACCEPTED_CHARACTER
from hloc.db_utils import recreate_db, create_session_for_process

logger = None

CODE_SEPARATOR = '#################'
LOCATION_RADIUS = 100
AIRPORT_LOCATION_CODES = []
LOCODE_LOCATION_CODES = []
CLLI_LOCATION_CODES = []
GEONAMES_LOCATION_CODES = []
STATES = []
TIMEOUT_URLS = []
MAX_POPULATION = 10000


def __create_parser_arguments(parser: argparse.ArgumentParser):
    """Creates the arguments for the parser"""
    parser.add_argument('-a', '--load-airport-codes', action='store_true',
                        dest='airport_codes',
                        help='download airport_codes from world-airport-codes.com')
    parser.add_argument('-o', '--load-offline-airport-codes', type=str,
                        help='Do not download'
                             ' the website but use the local files in the stated folder',
                        dest='offline_airportcodes')
    parser.add_argument('-le', '--locode', dest='locode', type=str,
                        help='Load locode codes from the 3 files: for example '
                             'collectedData/locodePart{}.csv {} is replaced with 1, 2, and 3')
    parser.add_argument('-c', '--clli', dest='clli', type=str,
                        help='Load clli codes from the path')
    parser.add_argument('-g', '--geo-names', type=str, dest='geonames',
                        help='Load geonames from the given path')
    parser.add_argument('-m', '--merge-locations', type=int,
                        dest='merge_radius',
                        help='Try to merge locations in the given radius by gps')
    parser.add_argument('-p', '--min-population', default=10000, type=int,
                        dest='min_population',
                        help='Specify the allowed minimum population for locations')
    parser.add_argument('-e', '--metropolitan-codes-file', dest='metropolitan_file', type=str,
                        help='Specify the metropolitan codes file')
    parser.add_argument('-l', '--logging-file', type=str, default='codes_parser.log',
                        dest='log_file',
                        help='Specify a logging file where the log should be saved')
    parser.add_argument('-ll', '--log-level', type=str, default='INFO', dest='log_level',
                        choices=['NOTSET', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the preferred log level')
    parser.add_argument('-d', '--database-recreate',  action='store_true',
                        help='Recreates the database structure. Attention deletes all data!')
    # TODO config file


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()

    if args.database_recreate:
        inp = input('Do you really want to recreate the database structure? (y)')
        if inp == 'y':
            recreate_db()

    global logger
    logger = setup_logger(args.log_file, 'parse_codes', loglevel=args.log_level)
    logger.debug('starting')

    parse_codes(args)


class WorldAirportCodesParser(HTMLParser):
    """
    A Parser which extends the standard Python HTMLParser
    to parse the airport detailed information side
    """
    airportInfo = None
    state = None
    __currentKey = None
    __th = False
    db_session = None

    def error(self, var1):
        raise NotImplementedError

    def handle_starttag(self, tag, attrs):
        attrs_dct = dict(attrs)
        if tag == 'h1' and ('class', 'airport-title') in attrs:
            self.__currentKey = 'precity_name'
        elif self.__currentKey == 'precity_name' and tag == 'p' and ('class', 'subheader') in attrs:
            self.__currentKey = 'city_name'
        elif tag == 'span' and ('class', 'airportAttributeValue') in attrs \
                and 'data-key' in attrs_dct and 'data-value' in attrs_dct \
                and attrs_dct['data-value']:
            if not self.airportInfo.airport_info:
                self.airportInfo.add_airport_info()

            # print(attrs_dct['data-key'], attrs_dct['data-value'].lower())
            if 'IATA' in attrs_dct['data-key']:
                self.airportInfo.airport_info.iata_codes.append(attrs_dct['data-value'].lower())
            elif 'ICAO' in attrs_dct['data-key']:
                self.airportInfo.airport_info.icao_codes.append(attrs_dct['data-value'].lower())
            elif 'FAA' in attrs_dct['data-key']:
                self.airportInfo.airport_info.faa_codes.append(attrs_dct['data-value'].lower())
            elif 'Latitude' in attrs_dct['data-key']:
                self.airportInfo.lat = float(attrs_dct['data-value'])
            elif 'Longitude' in attrs_dct['data-key']:
                self.airportInfo.lon = float(attrs_dct['data-value'])
        else:
            self.__currentKey = None

    def handle_endtag(self, tag):
        pass

    def handle_data(self, data):
        if self.__currentKey == 'city_name':
            name_split = data.split(',')

            if len(name_split) > 1:
                city_name = name_split[0].strip()
                state_string = name_split[-1].strip()
                self.airportInfo.name = city_name.lower()

                if set(self.airportInfo.name).difference(ACCEPTED_CHARACTER):
                    self.airportInfo.name = None

                state_code_index_s = state_string.find('(') + 1
                while state_string[state_code_index_s:].find('(') != -1:
                    state_code_index_s += state_string[state_code_index_s:].find('(') + 1

                state_code_index_e = state_string[state_code_index_s:].find(')') + \
                    state_code_index_s

                state_code = None
                if state_code_index_s > 0 and state_code_index_e > 0:
                    state_name = state_string[:(state_code_index_s - 1)].strip().lower()
                    state_code = state_string[state_code_index_s:state_code_index_e].lower()
                else:
                    state_name = state_string.strip().lower()

                self.state = state_for_code(state_code, state_name)

            self.__currentKey = None

    def reset(self):
        self.__currentKey = None
        self.__th = False
        self.airportInfo = LocationInfo()
        return HTMLParser.reset(self)


def load_pages_for_character(character: str, offline_path: str, request_session: requests.Session,
                             db_session: Session):
    """
    Loads the world-airport-codes side to the specific character, parses it
    and loops through all airports for the character. Loads their detailed page,
    parses that to location information and stores it into the LOCATION_CODES array.
    Additionally saves a copy of each detail page loaded to one file named:
        'page_locations_<character>'
    No return value
    """

    logger.debug('parser for character {0} startet'.format(character))

    if offline_path:
        load_detailed_pages_offline(character, offline_path, db_session)
        return

    url = 'https://www.world-airport-codes.com/alphabetical/city-name/' + \
        character + '.html'

    response = request_session.get(url)

    for _ in range(1, 5):
        if response.status_code == 200:
            break
        response = requests.get(url)

    if response.status_code != 200:
        response.raise_for_status()

    load_detailed_pages(response.text, character, request_session, db_session)
    # logger.debug('Parser for character {0} ended'.format(character))


def load_detailed_pages(page_code: str, character: str, request_session: requests.Session,
                        db_session: Session):
    """
    Parses the city Urls out of the page code and loads their pages to save them
    and also saves the parsed locations
    """
    search_string = '<tr class="table-link" onclick="document.location = \''
    index = page_code.find(search_string)
    count_timeouts = 0
    with open('pages_offline/page_locations_{0}.data'.format(character), 'w', encoding='utf-8') \
            as character_file:
        while index != -1:
            end_index = page_code[index + len(search_string):].find("'")
            city_url = 'https://www.world-airport-codes.com' + \
                page_code[index + len(search_string):index + len(search_string) + end_index]
            response = None
            try:
                response = request_session.get(city_url)
            except requests.exceptions.Timeout as ex:
                logger.exception(ex)
                sleep(5)
            if response is not None and response.status_code == 200:
                character_file.write(response.text)
                character_file.write(CODE_SEPARATOR)
                parse_airport_specific_page(response.text, db_session)
            else:
                TIMEOUT_URLS.append(city_url)
                count_timeouts += 1

            sleep(0.5)
            page_code = page_code[index + len(search_string) + end_index:]
            index = page_code.find(search_string)

    logger.debug('#timeouts for {}: {}'.format(character, count_timeouts))


def load_detailed_pages_offline(character: str, offline_path: str, db_session: Session):
    """
    Parsers all files for the character offline from the saved pages saved in
    './page_data/page_locations_<character>.data'
    """
    with open('{0}/page_locations_{1}.data'.format(offline_path, character), encoding='utf-8') \
            as character_file:
        page_code = ''
        for line in character_file:
            if CODE_SEPARATOR not in line:
                page_code = page_code + '\n' + line
            else:
                parse_airport_specific_page(page_code, db_session)
                page_code = ''


def parse_airport_specific_page(page_text: str, db_session: Session):
    """
    Parses from the page_text the the information
    Assumes the text is the HTML page code from a world-airport-codes page for
    detailed information about one airport and saves the location to the LOCATION_CODES
    """
    parser = WorldAirportCodesParser()
    body_start = page_text.find('<body')
    parser.db_session = db_session
    parser.feed(page_text[body_start:])

    if parser.airportInfo.name is not None and \
            (parser.airportInfo.airport_info.iata_codes or
             parser.airportInfo.airport_info.icao_codes or
             parser.airportInfo.airport_info.faa_codes):
        idfy_location(parser.airportInfo)
        parser.airportInfo.state = parser.state
        # db_session.add(parser.airportInfo)
        AIRPORT_LOCATION_CODES.append(parser.airportInfo)

    if len(AIRPORT_LOCATION_CODES) % 5000 == 0:
        logger.debug('saved {0} locations'.format(len(AIRPORT_LOCATION_CODES)))


# format of csv:
# [0]special,[1]countryCode,[2]placeCode,[3]name,[4]normalizedName,
# [5]subdivisionCode,[6]functionCodes,np,np,
# [9]iataCode(only if different from placeCode),[10]location,np
def get_locode_locations(locode_filename: str, db_session: Session):
    """
    Parses the locode information from a locode csv file and stores the
    locations into the LOCATION_CODES array
    """
    # i = 0
    with open(locode_filename, encoding='ISO-8859-1') as locode_file:
        current_state = None
        for line in locode_file:
            line_elements = line.split(',')
            # normally there are exactly 12 elements
            if len(line_elements) != 12:
                continue

            # a row which will be removed in the next locode pubblication
            if line_elements[0] == 'X':
                continue

            # if no place code is provided the line is a state definition line
            if len(line_elements[2]) == 0:
                current_state = state_for_code(normalize_locode_info(line_elements[1]),
                                               normalize_locode_info(line_elements[3])[1:])
                if not current_state:
                    print('Alert', normalize_locode_info(line_elements[1]),
                          normalize_locode_info(line_elements[3])[1:], sep=' ')
                continue

            if len(line_elements[6]) < 4:
                continue

            if line_elements[6][0] == '0' or line_elements[6][0:4] == '----':
                continue

            try:
                location_dict = get_location_from_locode_text(
                    normalize_locode_info(line_elements[10]))
            except ValueError:
                continue

            locode_name = get_locode_name(normalize_locode_info(line_elements[4]))
            if locode_name is None:
                continue

            # create a new entry
            airport_info = LocationInfo(**location_dict)
            if airport_info.lat == 'NaN' or airport_info.lon == 'NaN':
                continue

            airport_info.add_locode_info()
            airport_info.locode_info.place_codes.append(normalize_locode_info(
                line_elements[2]).lower())

            airport_info.name = locode_name.lower()
            idfy_location(airport_info)

            airport_info.state = current_state

            # db_session.add(airport_info)
            LOCODE_LOCATION_CODES.append(airport_info)


def normalize_locode_info(text: str):
    """remove "" at beginning and at the end and remove non utf8 character"""
    ret = ''
    for char in text[1:-1]:
        if char in printable:
            ret = '{0}{1}'.format(ret, char)
    return ret


def get_location_from_locode_text(locationtext: str):
    """converts the location text as found in the locode csv files into a LatLon object"""
    if len(locationtext) != 12:
        raise ValueError('The locationtext has to be exactly 12 characters long!')
    lat = int(locationtext[:2]) + float(locationtext[2:4])/60
    if locationtext[4] == 'S':
        lat = -lat
    lon = int(locationtext[6:9]) + float(locationtext[9:11])/60
    if locationtext[11] == 'W':
        lon = -lon

    # TODO return as tuple
    return {'lat': lat, 'lon': lon}


def get_locode_name(city_name: str):
    """if there is a '=' in the name extract the first part of the name"""
    if set(city_name).difference(ACCEPTED_CHARACTER):
        return None
    # FIXME not reachable
    if '=' in city_name:
        city_name = city_name.split('=')[0].strip()
    return city_name


def get_clli_codes(file_path: str, db_session: Session):
    """Get the clli codes from file ./collectedData/clli-lat-lon.txt"""
    with open(file_path) as clli_file:
        for line in clli_file:
            # [0:-1] remove last character \n and extract the information
            line = line.strip()
            clli, lat, lon = line.split('\t')
            new_clli_info = LocationInfo(lat=float(lat), lon=float(lon))
            new_clli_info.clli.append(clli[0:6])
            idfy_location(new_clli_info)
            # db_session.add(new_clli_info)
            CLLI_LOCATION_CODES.append(new_clli_info)


# 1: name               : name of geographical point (utf8) varchar(200)
# 2. asciiname          : name of geographical point in plain ascii characters, varchar(200)
# 3: alternatenames     : alternatenames, comma separated,
#                         convenience attribute from alternatename table, varchar(10000)
# 4: latitude           : latitude in decimal degrees (wgs84)
# 5: longitude          : longitude in decimal degrees (wgs84)
# 8: country code       : ISO-3166 2-letter country code, 2 characters
# 9: cc2                : alternate country codes, comma separated, ISO-3166 2-letter
#                         country code, 200 characters
# 14: population        : bigint (8 byte int)
def get_geo_names(file_path: str, min_population: int, db_session: Session):
    """Get the geo names from file ./collectedData/cities1000.txt"""

    with open(file_path, encoding='utf-8') as geoname_file:
        for line in geoname_file:
            # [0:-1] remove last character \n and extract the information
            columns = line[0:-1].split('\t')
            if len(columns) < 15:
                logger.debug(line)
                continue
            if len(columns[14]) == 0 or int(columns[14]) <= MAX_POPULATION:
                continue

            name = columns[1]
            if not name:
                continue

            alternatenames = columns[3].split(',')
            new_geo_names_info = LocationInfo(lat=float(columns[4]),
                                              lon=float(columns[5]),
                                              name=name)

            idfy_location(new_geo_names_info)
            if set(new_geo_names_info.name).difference(ACCEPTED_CHARACTER) \
                    or len(columns[14]) > 0 and int(columns[14]) < min_population:
                continue

            new_geo_names_info.name = columns[2].lower()

            if len(columns[9]) > 0:
                if columns[9].find(',') >= 0:
                    columns[9] = columns[9].split(',')[0]
                new_geo_names_info.state = state_for_code(columns[9].lower(), None,)

            new_geo_names_info.population = int(columns[14])

            for name in alternatenames:
                maxname = max(name.split(' '), key=len)

                if set(maxname).difference(ACCEPTED_CHARACTER):
                    continue
                if len(maxname) > 0:
                    new_geo_names_info.alternate_names.append(maxname.lower())

            # db_session.add(new_geo_names_info)
            GEONAMES_LOCATION_CODES.append(new_geo_names_info)


def location_merge(location1: LocationInfo, location2: LocationInfo, db_session: Session):
    """
    Merge location2 into location1
    location1 is the dominant one that means it defines the important properties
    """
    if location1.name is None:
        location1.name = location2.name

    if location1.state is not None and location2.state is not None and \
            location1.state != location2.state:
        raise ValueError('Location states do not match {} {}'.format(
            location1.name, location2.name))

    if location1.state is None:
        location1.state = location2.state

    if location2.state:
        location2.state.location_infos.remove(location2)

    location2.state = None

    if location2.locode_info:
        if location1.locode_info is None:
            location1.add_locode_info()
        location1.locode_info.place_codes.extend(location2.locode_info.place_codes)

    location1.clli.extend(location2.clli)

    if location2.airport_info:
        if location1.airport_info is None:
            location1.add_airport_info()

        location1.airport_info.iata_codes.extend(location2.airport_info.iata_codes)
        location1.airport_info.icao_codes.extend(location2.airport_info.icao_codes)
        location1.airport_info.faa_codes.extend(location2.airport_info.faa_codes)

    location1.alternate_names.extend(location2.alternate_names)

    if location2.name != location1.name:
        location1.alternate_names.append(location2.name)

    if location1.population is None:
        location1.population = location2.population


def merge_locations_to_location(location: LocationInfo, locations: [LocationInfo], radius: int,
                                db_session: Session, start: int=0):
    """Merge all locations from the locations list to the location if they are near enough"""
    near_locations = []

    for j in range(start, len(locations)):
        if location.is_in_radius(locations[j], radius):
            near_locations.append(locations[j])

    for mloc in near_locations:
        try:
            location_merge(location, mloc, db_session)
            locations.remove(mloc)
            del mloc
        except ValueError:
            continue


def add_locations(locations: [LocationInfo], to_add_locations: [LocationInfo], radius: int,
                  db_session: Session, create_new_locations: bool=True):
    """
    The first argument is a list which will not be condensed but the items
    of the second list will be matched on it. the remaining items in add_locations
    list will be added to list 1
    :param create_new_locations: Set false if the add_locations are not allowed to
        create new location objects Default is true
    """
    for i, location in enumerate(locations):
        merge_locations_to_location(location, to_add_locations, radius, db_session)

    if create_new_locations:
        merge_locations_by_gps(to_add_locations, radius, db_session)
        locations.extend(to_add_locations)
    else:
        for location in to_add_locations:
            if location.state:
                location.state.location_infos.remove(location)
                location.state = None


def merge_locations_by_gps(locations: [LocationInfo], radius: int, db_session: Session):
    """
    this method starts at the beginning and matches all locations which are in a
    range of `radius` kilometers
    """
    i = 0
    while i < len(locations):
        location = locations[i]
        i += 1
        lat_is_none = location.lat is None
        lon_is_none = location.lon is None
        if lat_is_none or lon_is_none:
            continue

        merge_locations_to_location(location, locations, radius, db_session, start=i)


def state_for_code(state_code, state_name):
    states_for_code = [state for state in STATES if state.iso3166code == state_code]
    if states_for_code:
        return states_for_code[0]

    state = State(name=state_name, iso3166code=state_code)
    STATES.append(state)
    return state


def idfy_location(location: LocationInfo):
    """
    Assign a unique id to every location in the array by computing the hash over all codes 
    sorted alphabetically. That should guarantee a unique and 
    """
    location.id = hashlib.md5('{}:{}'.format(location.lat, location.lon).encode()).hexdigest()


def parse_airport_codes(args, db_session: Session):
    """Parses the airport codes"""
    # for loop for all characters of the alphabet
    for character in list(ascii_lowercase):
        request_session = requests.Session()
        request_session.headers.update({'user-agent': 'HLOC code parser'})
        load_pages_for_character(character, args.offline_airportcodes, request_session, db_session)

    with open('timeoutUrls.json', 'w') as timeout_file:
        json.dump(TIMEOUT_URLS, timeout_file, indent=4)

    logger.debug('Finished airport codes parsing')


def parse_locode_codes(path, db_session: Session):
    """Parses the locode codes from the files"""
    locode_file1 = path.format(1)
    locode_file2 = path.format(2)
    locode_file3 = path.format(3)

    get_locode_locations(locode_file1, db_session)
    get_locode_locations(locode_file2, db_session)
    get_locode_locations(locode_file3, db_session)

    logger.debug('Finished locode parsing')


def merge_location_codes(merge_radius, db_session: Session):
    """
    Return all merged location codes if the option is set else return all codes
    concatenated
    """
    location_codes = []
    if merge_radius:
        logger.info('geonames length: {}'.format(len(GEONAMES_LOCATION_CODES)))
        logger.info('locode length: {}'.format(len(LOCODE_LOCATION_CODES)))
        logger.info('air length: {}'.format(len(AIRPORT_LOCATION_CODES)))
        logger.info('clli length: {}'.format(len(CLLI_LOCATION_CODES)))
        # location_codes = GEONAMES_LOCATION_CODES
        location_codes = sorted(GEONAMES_LOCATION_CODES,
                                key=lambda location: location.population,
                                reverse=True)
        merge_locations_by_gps(location_codes, merge_radius, db_session)

        locodes = sorted(LOCODE_LOCATION_CODES, key=lambda location: location.name)
        airport_codes = sorted(AIRPORT_LOCATION_CODES, key=lambda location: location.name)
        clli_codes = sorted(CLLI_LOCATION_CODES, key=lambda location: location.clli[0])
        # add_locations(location_codes, geo_codes)

        logger.info('geonames merged:{}'.format(len(location_codes)))
        add_locations(location_codes, locodes, merge_radius, db_session, create_new_locations=False)
        logger.info('locode merged:{}'.format(len(location_codes)))
        add_locations(location_codes, airport_codes, merge_radius, db_session)
        logger.info('air merged: {}'.format(len(location_codes)))
        add_locations(location_codes, clli_codes, merge_radius, db_session,
                      create_new_locations=False)
        logger.info('clli merged:{}'.format(len(location_codes)))

    else:
        location_codes.extend(AIRPORT_LOCATION_CODES)
        location_codes.extend(LOCODE_LOCATION_CODES)
        location_codes.extend(CLLI_LOCATION_CODES)
        location_codes.extend(GEONAMES_LOCATION_CODES)

    return location_codes


def print_stats(locations: [LocationInfo]):
    """Print stats for the collected codes"""
    iata_codes = 0
    locode_codes = 0
    icao_codes = 0
    faa_codes = 0
    clli_codes = 0
    geonames = 0
    for location in locations:
        if location.locode_info is not None:
            locode_codes += len(location.locode_info.place_codes)

        geonames += len(location.alternate_names)
        clli_codes += len(location.clli)

        if location.airport_info is not None:
            if len(location.airport_info.iata_codes) > 0:
                iata_codes += len(location.airport_info.iata_codes)
            if len(location.airport_info.icao_codes) > 0:
                icao_codes += len(location.airport_info.icao_codes)
            if len(location.airport_info.faa_codes) > 0:
                faa_codes += len(location.airport_info.faa_codes)

    logger.info('iata: {0} icao: {1} faa: {2} locode: {3} clli: {4} geonames: {5}'
                .format(iata_codes, icao_codes, faa_codes, locode_codes, clli_codes, geonames))


def parse_metropolitan_codes(metropolitan_filepath: str, db_session: Session) -> [LocationInfo]:
    """Parses the Iata metropolitan codes"""
    metropolitan_locations = []
    with open(metropolitan_filepath) as metropolitan_file:
        for line in metropolitan_file:
            code, lat, lon = line.strip().split(',')
            location = LocationInfo(lat=float(lat), lon=float(lon))
            idfy_location(location)
            location.add_airport_info()
            location.airport_info.iata_codes.append(code)
            metropolitan_locations.append(location)
            # db_session.add(location)

    return metropolitan_locations


def parse_codes(args):
    """start real parsing"""
    Session = create_session_for_process()
    db_session = Session()
    start_time = time.clock()
    start_rtime = time.time()
    try:
        with db_session.no_autoflush:
            if args.airport_codes:
                parse_airport_codes(args, db_session)
                if args.metropolitan_file:
                    metropolitan_locations = parse_metropolitan_codes(args.metropolitan_file,
                                                                      db_session)
                    if args.merge_radius:
                        add_locations(AIRPORT_LOCATION_CODES, metropolitan_locations, args.merge_radius,
                                      db_session, create_new_locations=False)
                    else:
                        add_locations(AIRPORT_LOCATION_CODES, metropolitan_locations, 100,
                                      db_session, create_new_locations=False)

            if args.locode:
                parse_locode_codes(args.locode, db_session)

            if args.clli:
                get_clli_codes(args.clli, db_session)
                logger.debug('Finished clli parsing')

            if args.geonames:
                get_geo_names(args.geonames, args.min_population, db_session)
                logger.debug('Finished geonames parsing')

        locations = merge_location_codes(args.merge_radius, db_session)

        db_session.bulk_save_objects(locations, return_defaults=True)

        db_session.commit()
    finally:
        db_session.close()
        Session.remove()

    end_time = time.clock()
    end_rtime = time.time()
    logger.debug('finished and needed {} seconds of the processor computation time\n'
                 'And {} seconds of the real world time.\n'
                 'Collected data on {} locations.'.format((end_time - start_time),
                                                          int(end_rtime - start_rtime),
                                                          len(locations)))


if __name__ == '__main__':
    main()
