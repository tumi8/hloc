#!/usr/bin/env python3
"""Some utility functions"""
from __future__ import print_function
from math import radians, cos, sin, asin, sqrt
from subprocess import check_output
from string import printable
from enum import Enum
import re
import json
import sys

ACCEPTED_CHARACTER = '{0},.-_'.format(printable[0:62])
DNS_REGEX = re.compile(r'^[a-zA-Z0-9\.\-_]+$', flags=re.MULTILINE)


#######################################
##    Different utility functions    ##
#######################################
def count_lines(filename):
    """"Opens the file at filename than counts and returns the number of lines"""
    count = check_output(['wc', '-l', filename])
    line_count = int(count.decode("utf-8") .split(' ')[0])

    print('Linecount for file: {0}'.format(line_count))
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
    for block in ip_blocks:
        hexdata += hex(int(block))[2:].zfill(2)
    return hexdata.upper()


def is_ip_hex_encoded_simple(ip_address, domain):
    """check if the ip address is encoded in hex format in the domain"""
    hex_ip = hex_for_ip(ip_address)

    return hex_ip.upper() in domain.upper()


def get_path_filename(path):
    """Extracts the filename from a path string"""
    if path[-1] == '/':
        raise NameError('The path leads to a directory')
    file_index = path.find('/')
    filename = path[:]

    while file_index >= 0:
        filename = filename[file_index + 1:]
        file_index = filename.find('/')

    return filename


#######################################
##     JSON utility functions        ##
#######################################
def json_object_encoding(obj):
    """Overrides the default method from the JSONEncoder"""
    if isinstance(obj, JSONBase):
        return obj.dict_representation()

    raise TypeError('Object not handled by the JSON encoding function')


def json_object_decoding(dct):
    """Decodes the dictionary to an object if it is one"""
    if '__class__' in dct:
        if dct['__class__'] == '__location__':
            return Location.create_object_from_dict(dct)
        if dct['__class__'] == '__airport_info__':
            return AirportInfo.create_object_from_dict(dct)
        if dct['__class__'] == '__locode_info__':
            return LocodeInfo.create_object_from_dict(dct)
        if dct['__class__'] == '__location_result__':
            return LocationResult.create_object_from_dict(dct)
        if dct['__class__'] == '__domain__':
            return Domain.create_object_from_dict(dct)
        if dct['__class__'] == '__domain_label__':
            return DomainLabel.create_object_from_dict(dct)
        if dct['__class__'] == '__domain_label_match__':
            return DomainLabelMatch.create_object_from_dict(dct)
        if dct['__class__'] == '__gps_location__':
            return GPSLocation.create_object_from_dict(dct)
    return dct


def json_dump(encoding_var, file_ptr, indent=0):
    """
    Dumps the encoding_var to the file in file_ptr with the
    json_object_encoding function
    :param encoding_var: the variable you want to encode in json
    :param file_ptr: the file where the
    :param indent: the indent for the dump call
    :return: None
    """
    json.dump(encoding_var, file_ptr, default=json_object_encoding,
              indent=indent)


def json_load(file_ptr):
    """
    Loads the content of the file and returns the decoded result
    :param file_ptr: the pointer to the file where json should load and decode
    :return: the variable from json.load
    """
    return json.load(file_ptr, object_hook=json_object_decoding)


def json_loads(json_str):
    """
    Decodes the content of the string variable and returns it
    :param json_str: the string which content should be decoded
    :return: the variable from json.loads
    """
    return json.loads(json_str, object_hook=json_object_decoding)


#######################################
##       Models and Interfaces       ##
#######################################
class LocationCodeType(Enum):
    iata = 'iata'
    icao = 'icao'
    faa = 'faa'
    clli = 'clli'
    locode = 'locode'
    geonames = 'geonames'

class JSONBase(object):
    """
    The Base class to JSON encode your object with json_encoding_func
    """

    __slots__ = []

    def dict_representation(self):
        raise NotImplementedError("JSONBase: Should have implemented this")

    @staticmethod
    def create_object_from_dict(dct):
        raise NotImplementedError("JSONBase: Should have implemented this")


class GPSLocation(JSONBase):
    """holds the coordinates"""

    __slots__ = ['_id', 'lat', 'lon']

    def __init__(self, lat, lon):
        """init"""
        self.id = None
        self.lat = lat
        self.lon = lon

    @property
    def id(self):
        """Getter for id"""
        return self._id

    @id.setter
    def id(self, new_id):
        """Setter for id"""
        if new_id is None:
            self._id = None
            return
        try:
            self._id = int(new_id)
        except (ValueError, TypeError):
            print('Error: GPSLocation.id must be an Integer!', file=sys.stderr)
            raise

    def is_in_radius(self, location, radius):
        """Returns a True if the location is within the radius with the equirectangular method"""
        lon1 = radians(float(self.lon))
        lat1 = radians(float(self.lat))
        lon2 = radians(float(location.lon))
        lat2 = radians(float(location.lat))
        # Radius of earth in kilometers. Use 3956 for miles
        return (((lon2 - lon1) * cos(0.5 * (lat2 + lat1))) ** 2 + (
            lat2 - lat1) ** 2) <= (radius / 6371) ** 2

    def gps_distance_equirectangular(self, location):
        """Return the distance between the two locations using the equirectangular method"""
        lon1 = radians(float(self.lon))
        lat1 = radians(float(self.lat))
        lon2 = radians(float(location.lon))
        lat2 = radians(float(location.lat))

        return sqrt((((lon2 - lon1) * cos(0.5 * (lat2 + lat1))) ** 2 + (
            lat2 - lat1) ** 2)) * 6371

    def gps_distance_haversine(self, location2):
        """
        Calculate the distance (km) between two points
        on the earth (specified in decimal degrees)
        """
        # convert decimal degrees to radians
        lon1 = radians(float(self.lon))
        lat1 = radians(float(self.lat))
        lon2 = radians(float(location2.lon))
        lat2 = radians(float(location2.lat))
        # haversine formula
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        tmp = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
        ftmp = 2 * asin(sqrt(tmp))
        # Radius of earth in kilometers. Use 3956 for miles
        return ftmp * 6371

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        ret_dict = {
            '__gps_location__': True,
            'lat': self.lat,
            'lon': self.lon
        }
        if self.id:
            ret_dict['id'] = self.id

        return ret_dict

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a Location object from a dictionary"""
        obj = GPSLocation(dct['lat'], dct['lon'])
        if 'id' in dct:
            obj.id = dct['id']
        return obj


class Location(GPSLocation):
    """
    A location object with the location name, coordinates and location codes
    Additionally information like the population can be saved
    """

    __slots__ = ['lat', 'lon', 'city_name', 'state', 'state_code', 'population',
                 'airport_info', 'locode', 'clli', 'alternate_names', 'nodes',
                 'available_nodes']

    def __init__(self, lat, lon, city_name=None, state=None, state_code=None,
                 population=0):
        """init"""
        self.city_name = city_name
        self.state = state
        self.state_code = state_code
        self.population = population
        self.airport_info = None
        self.locode = None
        self.clli = []
        self.alternate_names = []
        self.nodes = None
        self.available_nodes = None
        super().__init__(lat, lon)

    def add_airport_info(self):
        """Creates and sets a new empty AirportInfo object"""
        if self.airport_info is None:
            self.airport_info = AirportInfo()

    def add_locode_info(self):
        """Creates and sets a new empty """
        if self.locode is None:
            self.locode = LocodeInfo()

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        ret_dict = super().dict_representation()
        del ret_dict['__gps_location__']
        ret_dict.update({
            '__class__': '__location__',
            'city_name': self.city_name,
            'state': self.state,
            'state_code': self.state_code,
            'population': self.population,
            'clli': self.clli,
            'alternate_names': self.alternate_names
        })
        if self.airport_info:
            ret_dict['airport_info'] = self.airport_info.dict_representation()

        if self.locode:
            ret_dict['locode'] = self.locode.dict_representation()

        return ret_dict

    def code_id_type_tuples(self):
        """
        Creates a list with all codes in a tuple with the location id
        :rtype: list(tuple)
        """
        # if not isinstance(self.id, int):
        #     print(self.dict_representation(), 'has no id')
        #     raise ValueError('id is not int')
        ret_list = []
        if self.city_name:
            ret_list.append((self.city_name, (self.id, LocationCodeType.geonames)))
        for code in self.clli:
            ret_list.append((code, (self.id, LocationCodeType.clli)))
        for name in self.alternate_names:
            ret_list.append((name, (self.id, LocationCodeType.geonames)))
        if self.locode:
            for code in self.locode.place_codes:
                ret_list.append((code, (self.id, LocationCodeType.locode)))
        if self.airport_info:
            for code in self.airport_info.iata_codes:
                ret_list.append((code, (self.id, LocationCodeType.iata)))
            for code in self.airport_info.icao_codes:
                ret_list.append((code, (self.id, LocationCodeType.icao)))
            for code in self.airport_info.faa_codes:
                ret_list.append((code, (self.id, LocationCodeType.faa)))
        return ret_list

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a Location object from a dictionary"""
        obj = Location(dct['lat'], dct['lon'], dct['city_name'], dct['state'],
                       dct['state_code'], dct['population'])
        if 'id' in dct:
            obj.id = dct['id']
        if 'airport_info' in dct:
            obj.airport_info = dct['airport_info']
        if 'locode' in dct:
            obj.locode = dct['locode']
        return obj


class AirportInfo(JSONBase):
    """Holds a list of the different airport codes"""

    __slots__ = ['iata_codes', 'icao_codes', 'faa_codes']

    def __init__(self):
        """init"""
        self.iata_codes = []
        self.icao_codes = []
        self.faa_codes = []

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        return {
            '__class__': '__airport_info__',
            'iata_codes': self.iata_codes,
            'icao_codes': self.icao_codes,
            'faa_codes': self.faa_codes
        }

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a AirportInfo object from a dictionary"""
        obj = AirportInfo()
        obj.faa_codes = dct['faa_codes']
        obj.iata_codes = dct['iata_codes']
        obj.icao_codes = dct['icao_codes']
        return obj


class LocodeInfo(JSONBase):
    """Holds a list of locode codes"""

    __slots__ = ['place_codes', 'subdivision_codes']

    def __init__(self):
        """init"""
        self.place_codes = []
        self.subdivision_codes = []

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        return {
            '__class__': '__locode_info__',
            'place_codes': self.place_codes,
            'subdivision_codes': self.subdivision_codes
        }

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a LocodeInfo object from a dictionary"""
        obj = LocodeInfo()
        obj.place_codes = dct['place_codes']
        obj.subdivision_codes = dct['subdivision_codes']
        return obj


class Domain(JSONBase):
    """
    Holds the information for one domain
    DO NOT SET the DOMAIN NAME after calling the constructor!
    """

    __slots__ = ['domain_name', 'ip_address', 'ipv6_address', 'domain_labels',
                 'location']

    def __init__(self, domain_name, ip_address=None, ipv6_address=None):
        """init"""

        def create_labels():
            labels = []
            for label in domain_name.split('.')[::-1]:
                labels.append(DomainLabel(label, domain=self))
            return labels

        self.domain_name = domain_name
        self.ip_address = ip_address
        self.ipv6_address = ipv6_address
        self.domain_labels = create_labels()
        self.location = None

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        ret_dict = {
            '__class__': '__domain__',
            'domain_name': self.domain_name,
            'ip_address': self.ip_address,
            'ipv6_address': self.ipv6_address,
            'domain_labels': [label.dict_representation() for label in
                              self.domain_labels]
        }
        if self.location:
            ret_dict['location'] = self.location.id
        return ret_dict

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a Domain object from a dictionary"""
        obj = Domain(dct['domain_name'], dct['ip_address'], dct['ipv6_address'])
        if 'domain_labels' in dct:
            for label_dct in dct['domain_labels']:
                label_obj = label_dct
                label_obj.domain = obj
                obj.domain_labels.append(label_obj)

        return obj


class DomainLabel(JSONBase):
    """The model for a domain name label"""

    __slots__ = ['label', 'domain', 'matches']

    def __init__(self, label, domain=None):
        """
        init
        :param domain: set a reference to the domain name object
        """
        self.label = label
        self.domain = domain
        self.matches = []

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        return {
            '__class__': '__domain_label__',
            'label': self.label,
            'matches': [match.dict_representation() for match in self.matches]
        }

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a DomainLabel object from a dictionary"""
        obj = DomainLabel(dct['label'])
        for match in dct['matches']:
            match_obj = match
            match_obj.domain_label = obj
            obj.matches.append(match_obj)

        return obj


class DomainLabelMatch(JSONBase):
    """The model for a Match between a domain name label and a location code"""

    __slots__ = ['location_id', 'code_type', 'domain_label', 'code', 'matching']

    def __init__(self, location_id, code_type, domain_label=None, code=None):
        """init"""
        self.domain_label = domain_label
        self.location_id = location_id
        self.code_type = code_type
        self.code = code
        self.matching = False

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        return {
            '__class__': '__domain_label_match__',
            'location_id': self.location_id,
            'code_type': self.code_type,
            'matching': self.matching
        }

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a DomainLabel object from a dictionary"""
        obj = DomainLabelMatch(dct['location_id'], dct['code_type'])
        obj.matching = dct['matching']
        return obj


class LocationResult(JSONBase):
    """Stores the result for a location"""

    __slots__ = ['location_id', 'rtt', 'location']

    def __init__(self, location_id, rtt, location=None):
        """init"""
        self.location_id = location_id
        self.location = location
        self.rtt = rtt

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        return {
            '__class__': '__location_result__',
            'location_id': self.location_id,
            'rtt': self.rtt
        }

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a LocationResult object from a dictionary"""
        return LocationResult(dct['location_id'], dct['rtt'])
