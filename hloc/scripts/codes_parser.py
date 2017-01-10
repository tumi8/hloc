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
import re
import time
from string import ascii_lowercase
from string import printable
from threading import Semaphore
from threading import Thread
from time import sleep

import requests
from html.parser import HTMLParser

from hloc import util

CODE_SEPARATOR = '#################'
LOCATION_RADIUS = 100
THREADS_SEMA = None
LOCATION_CODES_SEMA = Semaphore()
AIRPORT_LOCATION_CODES = []
LOCODE_LOCATION_CODES = []
CLLI_LOCATION_CODES = []
GEONAMES_LOCATION_CODES = []
TIMEOUT_URLS = []
MAX_POPULATION = 10000
NORMAL_CHARS_REGEX = re.compile(r'^[a-zA-Z0-9/.-_\s]+$', flags=re.MULTILINE)  # TODO use set


class WorldAirportCodesParser(HTMLParser):
    """
    A Parser which extends the standard Python HTMLParser
    to parse the airport detailed information side
    """
    airportInfo = util.Location(None, None)
    __currentKey = None
    __th = False

    def error(self, var1):
        raise NotImplementedError

    def handle_starttag(self, tag, attrs):
        if tag == 'h3':
            self.__currentKey = 'cityName'
            self.__th = False
        elif tag == 'th' and ('width', '19%') in attrs:
            self.__th = True

    def handle_endtag(self, tag):
        self.__th = False
        if tag == 'td':
            self.__currentKey = None

    def handle_data(self, data):
        self.airportInfo.add_airport_info()
        if self.__th:
            if 'IATA' in data:
                self.__currentKey = 'iataCode'
            elif 'ICAO' in data:
                self.__currentKey = 'icaoCode'
            elif 'FAA' in data:
                self.__currentKey = 'faaCode'
            elif 'Latitude' in data:
                self.__currentKey = 'lat'
            elif 'Longitude' in data:
                self.__currentKey = 'lon'
            return
        elif self.__currentKey is None:
            return
        elif self.__currentKey == 'cityName':
            split_index = data.find(',') # use split
            city_name = data[:split_index]
            state_string = data[split_index + 2:]
            self.airportInfo.city_name = city_name.lower()
            if NORMAL_CHARS_REGEX.search(self.airportInfo.city_name) is None:
                self.airportInfo.city_name = None
            state_code_index_s = state_string.find('(') + 1
            state_code_index_e = state_string.find(')')
            if state_code_index_s > 0 and state_code_index_e > 0:
                self.airportInfo.state = state_string[:(state_code_index_s - 1)].strip().lower()
                self.airportInfo.state_code = state_string[
                                              state_code_index_s:state_code_index_e].lower()
            else:
                self.airportInfo.state = state_string.strip().lower()
        elif self.__currentKey == 'iataCode':
            self.airportInfo.airport_info.iata_codes.append(data.lower())
        elif self.__currentKey == 'icaoCode':
            self.airportInfo.airport_info.icao_codes.append(data.lower())
        elif self.__currentKey == 'faaCode':
            self.airportInfo.airport_info.faa_codes.append(data.lower())
        elif self.__currentKey == 'lat':
            self.airportInfo.lat = float(data)
        elif self.__currentKey == 'lon':
            self.airportInfo.lon = float(data)
        self.__currentKey = None

    def reset(self):
        self.__currentKey = None
        self.__th = False
        self.airportInfo = util.Location(None, None)
        return HTMLParser.reset(self)


def load_pages_for_character(character, offline_path):
    """
    Loads the world-airport-codes side to the specific character, parses it
    and loops through all airports for the character. Loads their detailed page,
    parses that to location information and stores it into the LOCATION_CODES array.
    Additionally saves a copy of each detail page loaded to one file named:
        'page_locations_<character>'
    No return value
    """

    print('Thread for character {0} startet'.format(character))

    if offline_path:
        load_detailed_pages_offline(character, offline_path)
        THREADS_SEMA.release()
        return

    url = 'https://www.world-airport-codes.com/alphabetical/city-name/' + \
        character + '.html'
    # TODO
    response = requests.get(url, timeout=3.05)
    for _ in range(1, 5):
        if response.status_code == 200:
            break
        response = requests.get(url, timeout=3.05)

    if response.status_code != 200:
        response.raise_for_status()

    load_detailed_pages(response.text, character)
    THREADS_SEMA.release()
    # print('Thread for character {0} ended'.format(character))


def load_detailed_pages(page_code, character):
    """
    Parses the city Urls out of the page code and loads their pages to save them
    and also saves the parsed locations
    """
    search_string = '<tr class="table-link" onclick="document.location = \''
    index = page_code.find(search_string)
    count_timeouts = 0
    with open('page_locations_{0}.data'.format(character), 'w', encoding='utf-8') \
            as character_file, \
            requests.Session() as session:
        while index != -1:
            end_index = page_code[index + len(search_string):].find("'")
            city_url = 'https://www.world-airport-codes.com' + \
                page_code[index + len(search_string):index + len(search_string) + end_index]
            response = None
            try:
                response = session.get(city_url, timeout=3.05)
            except requests.exceptions.Timeout as ex:
                print(ex)
                sleep(5)
            if response is not None and response.status_code == 200:
                character_file.write(response.text)
                character_file.write(CODE_SEPARATOR)
                parse_airport_specific_page(response.text)
            else:
                TIMEOUT_URLS.append(city_url)
                count_timeouts += 1

            sleep(0.5)
            page_code = page_code[index + len(search_string) + end_index:]
            index = page_code.find(search_string)

    print('#timeouts for ', character, ': ', count_timeouts)


def load_detailed_pages_offline(character, offline_path):
    """
    Parsers all files for the character offline from the saved pages saved in
    './page_data/page_locations_<character>.data'
    """
    with open('{0}/page_locations_{1}.data'.format(offline_path, character), encoding='utf-8') \
            as character_file:
        page_code = ''
        for line in character_file:
            if CODE_SEPARATOR not in line:
                page_code = '{0}\n{1}'.format(page_code, line)
            else:
                parse_airport_specific_page(page_code)
                page_code = ''


def parse_airport_specific_page(page_text):
    """
    Parses from the page_text the the information
    Assumes the text is the HTML page code from a world-airport-codes page for
    detailed information about one airport and saves the location to the LOCATION_CODES
    """
    city_start_search_string = '<h3 class="airport-title-sub">'
    city_end_search_string = '</table>'
    city_start_index = page_text.find(city_start_search_string)
    city_end_index = page_text[city_start_index:].find(city_end_search_string) \
        + city_start_index + len(city_end_search_string)
    code_to_parse = page_text[city_start_index:city_end_index]
    parser = WorldAirportCodesParser()
    parser.feed(code_to_parse)
    if parser.airportInfo.city_name is not None:
        LOCATION_CODES_SEMA.acquire()
        AIRPORT_LOCATION_CODES.append(parser.airportInfo)
        LOCATION_CODES_SEMA.release()

    if len(AIRPORT_LOCATION_CODES) % 5000 == 0:
        print('saved {0} locations'.format(len(AIRPORT_LOCATION_CODES)))


# format of csv:
# [0]special,[1]countryCode,[2]placeCode,[3]name,[4]normalizedName,
# [5]subdivisionCode,[6]functionCodes,np,np,
# [9]iataCode(only if different from placeCode),[10]location,np
def get_locode_locations(locode_filename):
    """
    Parses the locode information from a locode csv file and stores the
    locations into the LOCATION_CODES array
    """
    # i = 0
    with open(locode_filename, encoding='ISO-8859-1') as locode_file:
        current_state = {'state': None, 'state_code': None}
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
                current_state['state'] = normalize_locode_info(line_elements[3])[1:]
                current_state['state_code'] = normalize_locode_info(line_elements[1])
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

            # create a new entry
            airport_info = util.Location(**location_dict)
            airport_info.add_locode_info()
            airport_info.state_code = current_state['state_code'].lower()
            airport_info.locode.place_codes.append(normalize_locode_info(
                line_elements[2]).lower())
            locode_name = get_locode_name(normalize_locode_info(line_elements[4]))
            if locode_name is None:
                continue
            airport_info.city_name = locode_name.lower()
            airport_info.state = current_state['state'].lower()

            if airport_info.lat == 'NaN' or airport_info.lon == 'NaN':
                continue
            LOCATION_CODES_SEMA.acquire()
            LOCODE_LOCATION_CODES.append(airport_info)
            LOCATION_CODES_SEMA.release()

        THREADS_SEMA.release()


def normalize_locode_info(text):
    """remove "" at beginning and at the end and remove non utf8 character"""
    ret = ''
    for char in text[1:-1]:
        if char in printable:
            ret = '{0}{1}'.format(ret, char)
    return ret


# def set_locode_location(infoDict, locationtext):
#     """set the location from a locode location text in the infoDict"""
#     if len(locationtext) == 12:
#         location = get_location_from_locode_text(locationtext)
#         infoDict['lat'] = location['lat']
#         infoDict['lon'] = location['lon']
#     else:
#         infoDict['lat'] = 'NaN'
#         infoDict['lon'] = 'NaN'


def get_location_from_locode_text(locationtext):
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


def get_locode_name(city_name):
    """if there is a '=' in the name extract the first part of the name"""
    if NORMAL_CHARS_REGEX.search(city_name) is None:
        return None
    # FIXME not reachable
    if '=' in city_name:
        city_name = city_name.split('=')[0].strip()
    return city_name


def get_clli_codes(file_path):
    """Get the clli codes from file ./collectedData/clli-lat-lon.txt"""
    with open(file_path) as clli_file:
        for line in clli_file:
            # [0:-1] remove last character \n and extract the information
            line = line.strip()
            clli, lat, lon = line.split('\t')
            new_clli_info = util.Location(lat=float(lat), lon=float(lon))
            new_clli_info.clli.append(clli[0:6])
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
def get_geo_names(file_path, min_population):
    """Get the geo names from file ./collectedData/cities1000.txt"""

    with open(file_path, encoding='utf-8') as geoname_file:
        for line in geoname_file:
            # [0:-1] remove last character \n and extract the information
            columns = line[0:-1].split('\t')
            if len(columns) < 15:
                print(line)
                continue
            if len(columns[14]) == 0 or int(columns[14]) <= MAX_POPULATION:
                continue

            # name = columns[1]
            alternatenames = columns[3].split(',')
            new_geo_names_info = util.Location(lat=float(columns[4]), lon=float(columns[5]))
            new_geo_names_info.city_name = columns[2].lower()
            if NORMAL_CHARS_REGEX.search(new_geo_names_info.city_name) is None:
                continue

            if len(columns[9]) > 0:
                if columns[9].find(',') >= 0:
                    columns[9] = columns[9].split(',')[0]
                new_geo_names_info.state_code = columns[9].lower()

            if len(columns[14]) > 0 and int(columns[14]) >= min_population:
                new_geo_names_info.population = int(columns[14])
            else:
                continue

            for name in alternatenames:
                maxname = max(name.split(' '), key=len)

                if NORMAL_CHARS_REGEX.search(maxname) is None:
                    continue
                if len(maxname) > 0:
                    new_geo_names_info.alternate_names.append(maxname.lower())

            GEONAMES_LOCATION_CODES.append(new_geo_names_info)


def location_merge(location1, location2):
    """
    Merge location2 into location1
    location1 is the dominant one that means it defines the important properties
    """
    if location1.city_name is None:
        location1.city_name = location2.city_name
    if location2.state_code is None:
        location2.state_code = location1.state_code

    if location1.state_code is None:
        location1.state_code = location2.state_code

    # if location['stateCode'] is not None and loc['stateCode'] != location['stateCode']:
    #     # print('This locations states do not match:\n', location, '\n', loc)
    #     continue

    if location1.locode is None:
        location1.locode = location2.locode
    else:
        if location2.locode is not None:
            location1.locode.place_codes.extend(location2.locode.place_codes)

    location1.clli.extend(location2.clli)

    if location2.airport_info is not None:
        if location1.airport_info is None:
            location1.airport_info = location2.airport_info
        else:
            location1.airport_info.iata_codes.extend(location2.airport_info.iata_codes)
            location1.airport_info.icao_codes.extend(location2.airport_info.icao_codes)
            location1.airport_info.faa_codes.extend(location2.airport_info.faa_codes)
    location1.alternate_names.extend(location2.alternate_names)
    if location2.city_name != location1.city_name:
        location1.alternate_names.append(location2.city_name)


def merge_locations_to_location(location, locations, radius, start=0):
    """Merge all locations from the locations list to the location if they are near enough"""
    near_locations = []

    for j in range(start, len(locations)):
        if location.is_in_radius(locations[j], radius):
            near_locations.append(locations[j])

    for mloc in near_locations:
        location_merge(location, mloc)
        locations.remove(mloc)


def add_locations(locations, add_locations, radius, create_new_locations=True):
    """
    The first argument is a list which will not be condensed but the items
    of the second list will be matched on it. the remaining items in add_locations
    list will be added to list 1
    :param create_new_locations: Set false if the add_locations are not allowed to
        create new location objects Default is true
    """
    for i, location in enumerate(locations):
        merge_locations_to_location(location, add_locations, radius)

    if create_new_locations:
        merge_locations_by_gps(add_locations, radius)
        locations.extend(add_locations)


def merge_locations_by_gps(locations, radius):
    """
    this method starts at the beginning and matches all locations which are in a
    range of 30 kilometers
    """
    i = 0
    while i < len(locations):
        location = locations[i]
        i += 1
        lat_is_none = location.lat is None
        lon_is_none = location.lon is None
        if lat_is_none or lon_is_none:
            continue

        merge_locations_to_location(location, locations, radius, start=i)


def idfy_codes(codes):
    """Assign a unique id to every location in the array and return a dict with id to location"""
    ret_dict = {}
    for index, code in enumerate(codes):
        code.id = index
        ret_dict[index] = code

    return ret_dict


def parse_airport_codes(args):
    """Parses the airport codes"""
    # for loop for all characters of the alphabet
    threads = []
    for character in list(ascii_lowercase):
        # print('start Thread for character {0}'.format(character))
        THREADS_SEMA.acquire()
        thread = Thread(target=load_pages_for_character,
                        args=(character, args.offline_airportcodes))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    with open('timeoutUrls.json', 'w') as timeout_file:
        json.dump(TIMEOUT_URLS, timeout_file, indent=4)

    print('Finished airport codes parsing')


def parse_locode_codes(path):
    """Parses the locode codes from the files"""
    threads = []
    locode_file1 = path.format(1)
    locode_file2 = path.format(2)
    locode_file3 = path.format(3)
    # TODO do not use threads
    threads.append(Thread(target=get_locode_locations, args=(locode_file1,)))
    threads.append(Thread(target=get_locode_locations, args=(locode_file2,)))
    threads.append(Thread(target=get_locode_locations, args=(locode_file3,)))
    for thread in threads:
        THREADS_SEMA.acquire()
        thread.start()

    for thread in threads:
        thread.join()

    print('Finished locode parsing')


def merge_location_codes(merge_radius):
    """
    Return all merged location codes if the option is set else return all codes
    concatenated
    """
    location_codes = []
    if merge_radius:
        print('geonames length: ', len(GEONAMES_LOCATION_CODES))
        print('locode length: ', len(LOCODE_LOCATION_CODES))
        print('air length: ', len(AIRPORT_LOCATION_CODES))
        print('clli length: ', len(CLLI_LOCATION_CODES))
        # location_codes = GEONAMES_LOCATION_CODES
        location_codes = sorted(GEONAMES_LOCATION_CODES,
                                key=lambda location: location.population,
                                reverse=True)
        merge_locations_by_gps(location_codes, merge_radius)

        locodes = sorted(LOCODE_LOCATION_CODES, key=lambda location: location.city_name)
        airport_codes = sorted(AIRPORT_LOCATION_CODES, key=lambda location: location.city_name)
        clli_codes = sorted(CLLI_LOCATION_CODES, key=lambda location: location.clli[0])
        # add_locations(location_codes, geo_codes)

        print('geonames merged:', len(location_codes))
        add_locations(location_codes, locodes, merge_radius, create_new_locations=False)
        print('locode merged:', len(location_codes))
        add_locations(location_codes, airport_codes, merge_radius)
        print('air merged:', len(location_codes))
        add_locations(location_codes, clli_codes, merge_radius, create_new_locations=False)
        print('clli merged:', len(location_codes))

    else:
        location_codes.extend(AIRPORT_LOCATION_CODES)
        location_codes.extend(LOCODE_LOCATION_CODES)
        location_codes.extend(CLLI_LOCATION_CODES)
        location_codes.extend(GEONAMES_LOCATION_CODES)

    return location_codes


def print_stats(location_codes):
    """Print stats for the collected codes"""
    iata_codes = 0
    locode_codes = 0
    icao_codes = 0
    faa_codes = 0
    clli_codes = 0
    geonames = 0
    for location in location_codes:
        if location.locode is not None:
            locode_codes += len(location.locode.place_codes)
        geonames += len(location.alternate_names)
        clli_codes += len(location.clli)
        if location.airport_info is not None:
            if len(location.airport_info.iata_codes) > 0:
                iata_codes += len(location.airport_info.iata_codes)
            if len(location.airport_info.icao_codes) > 0:
                icao_codes += len(location.airport_info.icao_codes)
            if len(location.airport_info.faa_codes) > 0:
                faa_codes += len(location.airport_info.faa_codes)

    print('iata: {0} icao: {1} faa: {2} locode: {3} clli: {4} geonames: {5}'
          .format(iata_codes, icao_codes, faa_codes, locode_codes, clli_codes, geonames))


def parse_metropolitan_codes(metropolitan_filepath: str) -> [util.Location]:
    """Parses the Iata metropolitan codes"""
    metropolitan_locations = []
    with open(metropolitan_filepath) as metropolitan_file:
        for line in metropolitan_file:
            code, lat, lon = line.strip().split(',')
            location = util.Location(lat=float(lat), lon=float(lon))
            location.add_airport_info()
            location.airport_info.iata_codes.append(code)
            metropolitan_locations.append(location)

    return metropolitan_locations


def parse_codes(args):
    """start real parsing"""
    start_time = time.clock()
    start_rtime = time.time()
    if args.airport_codes:
        parse_airport_codes(args)
        if args.metropolitan_file:
            metropolitan_locations = parse_metropolitan_codes(args.metropolitan_file)
            if args.merge_radius:
                add_locations(AIRPORT_LOCATION_CODES, metropolitan_locations, args.merge_radius,
                              create_new_locations=False)
            else:
                add_locations(AIRPORT_LOCATION_CODES, metropolitan_locations, 100,
                              create_new_locations=False)

    if args.locode:
        parse_locode_codes(args.locode)

    if args.clli:
        get_clli_codes(args.clli)
        print('Finished clli parsing')

    if args.geonames:
        get_geo_names(args.geonames, args.min_population)
        print('Finished geonames parsing')

    location_codes = merge_location_codes(args.merge_radius)

    locations = idfy_codes(location_codes)
    with open(args.filename, 'w') as character_codes_file:
        util.json_dump(locations, character_codes_file)
        
    end_time = time.clock()
    end_rtime = time.time()
    print('finished and needed ', (end_time - start_time), ' seconds of the'
          'processor computation time\nAnd ', int(end_rtime - start_rtime),
          ' seconds of the real world time.\nCollected data on ', len(location_codes),
          ' locations.')

    print_stats(location_codes)


def __create_parser_arguments(parser):
    """Creates the arguments for the parser"""
    parser.add_argument('-a', '--load-airport-codes', action='store_true',
                        dest='airport_codes',
                        help='download airport_codes from world-airport-codes.com')
    parser.add_argument('-o', '--load-offline-airport-codes', type=str,
                        help='Do not download'
                             ' the website but use the local files in the stated folder',
                        dest='offline_airportcodes')
    parser.add_argument('-l', '--locode', dest='locode', type=str,
                        help='Load locode codes from the 3 files: for example '
                        'collectedData/locodePart{}.csv {} is replaced with 1, 2, and 3')
    parser.add_argument('-c', '--clli', dest='clli', type=str,
                        help='Load clli codes from the path')
    parser.add_argument('-g', '--geo-names', type=str, dest='geonames',
                        help='Load geonames from the given path')
    parser.add_argument('-m', '--merge-locations', type=int,
                        dest='merge_radius',
                        help='Try to merge locations in the given radius by gps')
    parser.add_argument('-t', '--max-threads', default=16, type=int,
                        dest='maxThreads',
                        help='Specify the maximal amount of threads')
    parser.add_argument('-p', '--min-population', default=10000, type=int,
                        dest='min_population',
                        help='Specify the allowed minimum population for locations')
    parser.add_argument('-f', '--output-filename', type=str,
                        default='collectedData.json',
                        dest='filename', help='Specify the output filename')
    parser.add_argument('-e', '--metropolitan-codes-file', dest='metropolitan_file', type=str,
                        help='Specify the metropolitan codes file')
    # TODO config file


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    __create_parser_arguments(parser)
    args = parser.parse_args()
    global THREADS_SEMA
    THREADS_SEMA = Semaphore(args.maxThreads)
    parse_codes(args)


if __name__ == '__main__':
    main()
