#!/usr/bin/env python
"""
Get airport locations form world-airport-codes.com, the UN/LOCODE codes from files
in ./collectedData/locodePart{1,2,3}.csv and save it to ./collectedData.json

population sortieren
die clli bei 6 abschneiden
"""
from __future__ import print_function
import requests
import json
import time
import re
import argparse
from string import ascii_lowercase
from string import printable
from math import radians, cos, sin, asin, sqrt
from time import sleep
try:
    from html.parser import HTMLParser
except ImportError:
    from HTMLParser import HTMLParser
from threading import Thread
from threading import Semaphore

CODE_SEPARATOR = '#################'
LOCATION_RADIUS = 30
LOCATION_RADIUS_PRECOMPUTED = (LOCATION_RADIUS / 6371)**2
THREADS_SEMA = None
LOCATION_CODES_SEMA = Semaphore(1)
AIRPORT_LOCATION_CODES = []
LOCODE_LOCATION_CODES = []
CLLI_LOCATION_CODES = []
GEONAMES_LOCATION_CODES = []
TIMEOUT_URLS = []
MAX_POPULATION = 10000
NORMAL_CHARS_REGEX = re.compile(r'^[a-zA-Z0-9\.\-_]+$', flags=re.MULTILINE)
# STATE_CODES = ['AL', 'LA', 'OH', 'AK', 'ME', 'OK', 'AS', 'MH', 'OR', 'AZ', 'MD', 'PW', 'AR',
#                'MA', 'PA', 'CA', 'MI', 'RI', 'CO', 'FM', 'SC', 'CT', 'MN', 'SD', 'DE', 'MS',
#                'TN', 'DC', 'MO', 'TX', 'FL', 'MT', 'UT', 'GA', 'NE', 'VT', 'GU', 'NV', 'VI',
#                'HI', 'NH', 'VA', 'ID', 'NJ', 'WA', 'IL', 'NM', 'WV', 'IN', 'NY', 'WI', 'IA',
#                'NC', 'WY', 'KS', 'ND', 'KY', 'MP']


def get_standard_location_info():
    """Creates a standardized dict to store location information and returns it"""
    return {
        'cityName': None, 'state': None, 'lat': None, 'lon': None,
        'airportInfo': None, 'locode': None, 'clli': [], 'alternateNames': [],
        'stateCode': None, 'population': 0
        }


def get_standard_locairport_info():
    """Creates a standardized dict to store locations with an airport and returns it"""
    ret = get_standard_location_info()
    ret['airportInfo'] = get_standard_airport_info()
    return ret


def get_standard_airport_info():
    """Creates a standardized dict to store airport information and returns it"""
    return {'iataCode': [], 'icaoCode': [], 'faaCode': []}


def get_standard_locode_info():
    """Creates a standardized dict to store locode information and returns it"""
    return {'placeCodes': [], 'subdivisionCode': None}


class WorldAirportCodesParser(HTMLParser):
    """
    A Parser which extends the standard Python HTMLParser
    to parse the airport detailed information side
    """
    airportInfo = get_standard_locairport_info()
    __currentKey = None
    __th = False

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
            splitIndex = data.find(',')
            cityName = data[:splitIndex]
            stateString = data[splitIndex + 2:]

            self.airportInfo['cityName'] = cityName.lower()
            if NORMAL_CHARS_REGEX.search(self.airportInfo['cityName']) is None:
                self.airportInfo['cityName'] = None
            stateCodeIndexS = stateString.find('(') + 1
            stateCodeIndexE = stateString.find(')')
            if stateCodeIndexS > 0 and stateCodeIndexE > 0:
                self.airportInfo['state'] = stateString[:(stateCodeIndexS - 1)].strip().lower()
                self.airportInfo['stateCode'] = stateString[stateCodeIndexS:stateCodeIndexE].lower()
            else:
                self.airportInfo['state'] = stateString.strip().lower()
        elif self.__currentKey == 'iataCode':
            self.airportInfo['airportInfo']['iataCode'].append(data.lower())
        elif self.__currentKey == 'icaoCode':
            self.airportInfo['airportInfo']['icaoCode'].append(data.lower())
        elif self.__currentKey == 'faaCode':
            self.airportInfo['airportInfo']['faaCode'].append(data.lower())
        elif self.__currentKey == 'lat':
            self.airportInfo['lat'] = float(data)
        elif self.__currentKey == 'lon':
            self.airportInfo['lon'] = float(data)
        self.__currentKey = None

    def reset(self):
        self.__currentKey = None
        self.__th = False
        self.airportInfo = get_standard_locairport_info()
        return HTMLParser.reset(self)


def load_pages_for_character(character, offlinePath):
    """
    Loads the world-airport-codes side to the specific character, parses it
    and loops through all airports for the character. Loads their detailed page,
    parses that to location information and stores it into the LOCATION_CODES array.
    Additionally saves a copy of each detail page loaded to one file named:
        'page_locations_<character>'
    No return value
    """

    print('Thread for character {0} startet'.format(character))

    if offlinePath:
        load_detailed_pages_offline(character, offlinePath)
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


def load_detailed_pages(pageCode, character):
    """
    Parses the city Urls out of the page code and loads their pages to save them
    and also saves the parsed locations
    """
    searchString = '<tr class="table-link" onclick="document.location = \''
    index = pageCode.find(searchString)
    countTimeouts = 0
    characterFile = open('page_locations_{0}.data'.format(character), 'w', encoding='utf-8')
    session = requests.Session()

    while index != -1:
        endIndex = pageCode[index + len(searchString):].find("'")
        cityUrl = 'https://www.world-airport-codes.com' + \
            pageCode[index + len(searchString):index + len(searchString) + endIndex]
        response = None
        try:
            response = session.get(cityUrl, timeout=3.05)
        except requests.exceptions.Timeout as ex:
            print(ex)
            sleep(5)
        if response is not None and response.status_code == 200:
            characterFile.write(response.text)
            characterFile.write(CODE_SEPARATOR)
            parse_airport_specific_page(response.text)
        else:
            TIMEOUT_URLS.append(cityUrl)
            countTimeouts += 1

        sleep(0.5)
        pageCode = pageCode[index + len(searchString) + endIndex:]
        index = pageCode.find(searchString)

    characterFile.close()
    print('#timeouts for ', character, ': ', countTimeouts)


def load_detailed_pages_offline(character, offlinePath):
    """
    Parsers all files for the character offline from the saved pages saved in
    './page_data/page_locations_<character>.data'
    """
    characterFile = open('{0}/page_locations_{1}.data'.format(offlinePath, character),
                         'r', encoding='utf-8')
    pageCode = ''
    for line in characterFile:
        if CODE_SEPARATOR not in line:
            pageCode = '{0}\n{1}'.format(pageCode, line)
        else:
            parse_airport_specific_page(pageCode)
            pageCode = ''

    characterFile.close()


def parse_airport_specific_page(pageText):
    """
    Parses from the pageText the the information
    Assumes the text is the HTML page code from a world-airport-codes page for
    detailed information about one airport and saves the location to the LOCATION_CODES
    """
    cityStartSearchString = '<h3 class="airport-title-sub">'
    cityEndSearchString = '</table>'
    cityStartIndex = pageText.find(cityStartSearchString)
    cityEndIndex = pageText[cityStartIndex:].find(cityEndSearchString) \
        + cityStartIndex + len(cityEndSearchString)
    codeToParse = pageText[cityStartIndex:cityEndIndex]
    parser = WorldAirportCodesParser()
    parser.feed(codeToParse)
    if parser.airportInfo['cityName'] is not None:
        LOCATION_CODES_SEMA.acquire()
        AIRPORT_LOCATION_CODES.append(parser.airportInfo)
        LOCATION_CODES_SEMA.release()

    if len(AIRPORT_LOCATION_CODES) % 5000 == 0:
        print('saved {0} locations'.format(len(AIRPORT_LOCATION_CODES)))


# format of csv:
# [0]special,[1]countryCode,[2]placeCode,[3]name,[4]normalizedName,
# [5]subdivisionCode,[6]functionCodes,np,np,
# [9]iataCode(only if different from placeCode),[10]location,np
def get_locode_locations(locodeFilename):
    """
    Parses the locode information from a locode csv file and stores the
    locations into the LOCATION_CODES array
    """
    i = 0
    with open(locodeFilename, 'r', encoding='ISO-8859-1') as locodeFile:
        currentState = {'state': None, 'stateCode': None}
        for line in locodeFile:
            lineElements = line.split(',')
            # normally there are exactly 12 elements
            if len(lineElements) != 12:
                continue

            # a row which will be removed in the next locode pubblication
            if lineElements[0] == 'X':
                continue

            # if no place code is provided the line is a state definition line
            if len(lineElements[2]) == 0:
                currentState['state'] = normalize_locode_info(lineElements[3])[1:]
                currentState['stateCode'] = normalize_locode_info(lineElements[1])
                continue

            if len(lineElements[6]) < 4:
                continue

            if lineElements[6][0] == '0' or lineElements[6][0:4] == '----':
                continue

            # create new entry
            airportInfo = get_standard_location_info()
            airportInfo['locode'] = get_standard_locode_info()
            airportInfo['stateCode'] = currentState['stateCode'].lower()
            airportInfo['locode']['placeCodes'].append(normalize_locode_info(
                lineElements[2]).lower())
            airportInfo['locode']['subdivisionCode'] = normalize_locode_info(
                lineElements[5]).lower()
            locodeName = get_locode_name(normalize_locode_info(lineElements[4]))
            if locodeName is None:
                continue
            airportInfo['cityName'] = locodeName.lower()
            airportInfo['state'] = currentState['state'].lower()

            set_locode_location(airportInfo, normalize_locode_info(lineElements[10]))
            if airportInfo['lat'] == 'NaN' or airportInfo['lon'] == 'NaN':
                continue
            LOCATION_CODES_SEMA.acquire()
            LOCODE_LOCATION_CODES.append(airportInfo)
            LOCATION_CODES_SEMA.release()
            # if len(LOCATION_CODES) % 5000 == 0:
            #     print('read {0} UN/LOCODE lines'.format(len(LOCATION_CODES)))

        THREADS_SEMA.release()


def normalize_locode_info(text):
    """remove "" at beginning and at the end and remove non utf8 character"""
    ret = ''
    for char in text[1:-1]:
        if char in printable:
            ret = '{0}{1}'.format(ret, char)
    return ret


def set_locode_location(infoDict, locationtext):
    """set the location from a locode location text in the infoDict"""
    if len(locationtext) == 12:
        location = get_location_from_locode_text(locationtext)
        infoDict['lat'] = location['lat']
        infoDict['lon'] = location['lon']
    else:
        infoDict['lat'] = 'NaN'
        infoDict['lon'] = 'NaN'


def get_location_from_locode_text(locationtext):
    # 48.15 11.583
    """converts the location text as found in the locode csv files into a LatLon object"""
    lat = int(locationtext[:2]) + float(locationtext[2:4])/60
    if locationtext[4] == 'S':
        lat = -lat
    lon = int(locationtext[6:9]) + float(locationtext[9:11])/60
    if locationtext[11] == 'W':
        lon = -lon

    return {'lat': lat, 'lon': lon}


def get_locode_name(cityName):
    """if there is a '=' in the name extract the first part of the name"""
    if NORMAL_CHARS_REGEX.search(cityName) is None:
        return None
    if '=' in cityName:
        cityName = cityName.split('=')[0].strip()
    return cityName


def get_clli_codes():
    """Get the clli codes from file ./collectedData/clli-lat-lon.txt"""
    with open('collectedData/clli-lat-lon.txt', 'r') as clliFile:
        for line in clliFile:
            # [0:-1] remove last character \n and extract the information
            clli, lat, lon = line[0:-1].split('\t')
            newClliInfo = get_standard_location_info()
            newClliInfo['clli'].append(clli[0:6])
            newClliInfo['lat'] = float(lat)
            newClliInfo['lon'] = float(lon)
            CLLI_LOCATION_CODES.append(newClliInfo)


def get_geo_names():
    """Get the geo names from file ./collectedData/allCountries.txt"""

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
    with open('collectedData/cities1000.txt', 'r') as clliFile:
        for line in clliFile:
            # [0:-1] remove last character \n and extract the information
            columns = line[0:-1].split('\t')
            if len(columns) < 15:
                print(line)
                continue
            if len(columns[14]) == 0 or int(columns[14]) <= MAX_POPULATION:
                continue

            # name = columns[1]
            alternatenames = columns[3].split(',')
            newGeoNamesInfo = get_standard_location_info()
            newGeoNamesInfo['cityName'] = columns[2].lower()
            if NORMAL_CHARS_REGEX.search(newGeoNamesInfo['cityName']) is None:
                continue
            newGeoNamesInfo['lat'] = float(columns[4])
            newGeoNamesInfo['lon'] = float(columns[5])
            if len(columns[9]) > 0:
                if columns[9].find(',') >= 0:
                    columns[9] = columns[9].split(',')[0]
                newGeoNamesInfo['stateCode'] = columns[9].lower()
            if len(columns[14]) > 0:
                newGeoNamesInfo['population'] = int(columns[14])

            for name in alternatenames:
                maxname = max(name.split(' '), key=len)

                if NORMAL_CHARS_REGEX.search(maxname) is None:
                    continue
                if len(maxname) > 0:
                    newGeoNamesInfo['alternateNames'].append(maxname.lower())

            GEONAMES_LOCATION_CODES.append(newGeoNamesInfo)


def gps_distance_haversine(location1, location2):
    """
    Calculate the distance (km) between two points
    on the earth (specified in decimal degrees)
    """
    # convert decimal degrees to radians
    lon1 = radians(float(location1['lon']))
    lat1 = radians(float(location1['lat']))
    lon2 = radians(float(location2['lon']))
    lat2 = radians(float(location2['lat']))
    # haversine formula
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a))
    # Radius of earth in kilometers. Use 3956 for miles
    return c * 6371


def is_in_radius(location1, location2):
    """
    Calculate the distance (km) between two points
    using the equirectangular distance approximation
    """
    lon1 = radians(float(location1['lon']))
    lat1 = radians(float(location1['lat']))
    lon2 = radians(float(location2['lon']))
    lat2 = radians(float(location2['lat']))
    # Radius of earth in kilometers. Use 3956 for miles
    return LOCATION_RADIUS_PRECOMPUTED >= (((lon2 - lon1) * cos(0.5*(lat2+lat1)))**2 +
                                           (lat2 - lat1)**2)


def location_merge(location1, location2):
    """
    Merge location2 into location1
    location1 is the dominant one that means it defines the important properties
    """
    if location2['stateCode'] is None:
        location2['stateCode'] = location1['stateCode']

    if location1['stateCode'] is None:
        location1['stateCode'] = location2['stateCode']

    # if location['stateCode'] is not None and loc['stateCode'] != location['stateCode']:
    #     # print('This locations states do not match:\n', location, '\n', loc)
    #     continue

    if location1['locode'] is None:
        location1['locode'] = location2['locode']
    else:
        if location2['locode'] is not None:
            location1['locode']['placeCodes'].extend(location2['locode']['placeCodes'])

    location1['clli'].extend(location2['clli'])

    if location2['airportInfo'] is not None:
        if location1['airportInfo'] is None:
            location1['airportInfo'] = location2['airportInfo']
        else:
            location1['airportInfo']['iataCode'].extend(location2['airportInfo']['iataCode'])
            location1['airportInfo']['icaoCode'].extend(location2['airportInfo']['icaoCode'])
            location1['airportInfo']['faaCode'].extend(location2['airportInfo']['faaCode'])
    location1['alternateNames'].extend(location2['alternateNames'])


def merge_locations_to_location(location, locations, start=0):
    """Merge all locations from the locations list to the location if they are near enaugh"""
    nearLocations = []

    for j in range(start, len(locations)):
        if is_in_radius(location, locations[j]):
            nearLocations.append(locations[j])

    for mloc in nearLocations:
        location_merge(location, mloc)
        locations.remove(mloc)


def add_locations(locations, addLocations):
    """
    The first argument is a list which will not be condesed but the items
    of the second list will be matched on it. the remaining items in addLocations
    list will be added to list 1
    """
    i = 0
    while i < len(locations):
        location = locations[i]
        i = i + 1
        merge_locations_to_location(location, addLocations)
    # merge_locations_by_gps(addLocations)
    # locations.extend(addLocations)


def merge_locations_by_gps(locations):
    """
    this method starts at the beginning and matches all locations which are in a
    range of 30 kilometers
    """
    i = 0
    while i < len(locations):
        location = locations[i]

        if location['cityName'] != 'Munich'.lower():
            continue
        i = i + 1
        if location['lat'] is None or location['lon'] is None:
            continue

        merge_locations_to_location(location, locations, start=i)


def idfy_codes(codes):
    """Assign a unique id to every location in the array and return a dict with id to location"""
    ret_dict = {}
    for index in range(0, len(codes)):
        codes[index]['id'] = str(index)
        ret_dict[str(index)] = codes[index]

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

    timeoutFile = open('timeoutUrls.json', 'w')
    json.dump(TIMEOUT_URLS, timeoutFile, indent=4)
    timeoutFile.close()
    print('Finished airport codes parsing')


def parse_locode_codes(args):
    """Parses the locode codes from the files"""
    threads = []
    locodeFile1 = 'collectedData/locodePart1.csv'
    locodeFile2 = 'collectedData/locodePart2.csv'
    locodeFile3 = 'collectedData/locodePart3.csv'
    threads.append(Thread(target=get_locode_locations, args=(locodeFile1,)))
    threads.append(Thread(target=get_locode_locations, args=(locodeFile2,)))
    threads.append(Thread(target=get_locode_locations, args=(locodeFile3,)))
    for thread in threads:
        THREADS_SEMA.acquire()
        thread.start()

    for thread in threads:
        thread.join()

    print('Finished locode parsing')


def merge_location_codes(args):
    """
    Return all merged location codes if the option is set else return all codes
    concatenated
    """
    location_codes = []
    if args.merge:
        print('geonames length: ', len(GEONAMES_LOCATION_CODES))
        print('locode length: ', len(LOCODE_LOCATION_CODES))
        print('air length: ', len(AIRPORT_LOCATION_CODES))
        print('clli length: ', len(CLLI_LOCATION_CODES))
        location_codes = GEONAMES_LOCATION_CODES
        merge_locations_by_gps(location_codes)
        # geo_codes = sorted(GEONAMES_LOCATION_CODES,
        #                    key=lambda location: location['population'],
        #                    reverse=True)
        locodes = sorted(LOCODE_LOCATION_CODES, key=lambda location: location['cityName'])
        airport_codes = sorted(AIRPORT_LOCATION_CODES, key=lambda location: location['cityName'])
        clli_codes = sorted(CLLI_LOCATION_CODES, key=lambda location: location['clli'][0])
        # add_locations(location_codes, geo_codes)

        print('geonames merged: ', len(location_codes))
        add_locations(location_codes, locodes)
        print('locode merged', len(location_codes))
        add_locations(location_codes, airport_codes)
        print('air merged', len(location_codes))
        add_locations(location_codes, clli_codes)
        print('clli merged', len(location_codes))

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
        if location['locode'] is not None:
            locode_codes = locode_codes + len(location['locode']['placeCodes'])
        geonames = geonames + len(location['alternateNames'])
        clli_codes = clli_codes + len(location['clli'])
        if location['airportInfo'] is not None:
            if len(location['airportInfo']['iataCode']) > 0:
                iata_codes = iata_codes + len(location['airportInfo']['iataCode'])
            if len(location['airportInfo']['icaoCode']) > 0:
                icao_codes = icao_codes + len(location['airportInfo']['icaoCode'])
            if len(location['airportInfo']['faaCode']) > 0:
                faa_codes = faa_codes + len(location['airportInfo']['faaCode'])

    print('iata: {0} icao: {1} faa: {2} locode: {3} clli: {4} geonames: {5}'
          .format(iata_codes, icao_codes, faa_codes, locode_codes, clli_codes, geonames))


def parse_codes(args):
    """start real parsing"""
    startTime = time.clock()
    startRTime = time.time()
    if args.airport_codes:
        parse_airport_codes(args)

    if args.locode:
        parse_locode_codes(args)

    if args.clli:
        get_clli_codes()
        print('Finished clli parsing')

    if args.geonames:
        get_geo_names()
        print('Finished geonames parsing')

    location_codes = merge_location_codes(args)

    locations = idfy_codes(location_codes)
    characterCodesFile = open(args.filename, 'w')
    json.dump(locations, characterCodesFile, indent=4)
    characterCodesFile.close()
    endTime = time.clock()
    endRTime = time.time()
    print('finished and needed ', (endTime - startTime), ' seconds of the'
          'processor computation time\nAnd ', int(endRTime - startRTime),
          ' seconds of the real world time.\nCollected data on ', len(location_codes),
          ' locations.')

    print_stats(location_codes)


def main():
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--load-airport-codes', action='store_true', dest='airport_codes',
                        help='load airport_codes from world-airport-codes.com')
    parser.add_argument('-o', '--load-offline-airport-codes', type=str, help='Do not load'
                        ' the website but use the local files in the stated folder',
                        dest='offline_airportcodes')
    parser.add_argument('-l', '--locode', action='store_true', dest='locode',
                        help='Load locode codes from ./collectedData/locodePart{1,2,3}.csv')
    parser.add_argument('-c', '--clli', action='store_true', dest='clli',
                        help='Load clli codes from ./collectedData/clli-lat-lon.txt')
    parser.add_argument('-g', '--geo-names', action='store_true', dest='geonames',
                        help='Load geonames from ./collectedData/allCountries.txt')
    parser.add_argument('-m', '--merge-locations', action='store_true', dest='merge',
                        help='Try to merge locations by gps')
    parser.add_argument('-t', '--max-threads', default=16, type=int, dest='maxThreads',
                        help='Specify the maximal amount of threads')
    parser.add_argument('-f', '--output-filename', type=str, default='collectedData.json',
                        dest='filename', help='Specify the output filename')
    # parser.add_argument('-f', '--add-to-file', type=str, dest='file',
    #                     help='Specify a file where to add the location information')
    args = parser.parse_args()
    global THREADS_SEMA
    THREADS_SEMA = Semaphore(args.maxThreads)
    # if args.file:
    #     try:
    #         locationFile = open(args.file, 'r')
    #         global LOCATION_CODES
    #         LOCATION_CODES = json.load(locationFile)
    #         locationFile.close()
    #     except Exception:
    #         print('use a valid filepath for the -f argument!')
    #         raise

    parse_codes(args)


if __name__ == '__main__':
    main()
