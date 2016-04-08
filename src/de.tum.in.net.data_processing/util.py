#!/usr/bin/env python3
"""Some utility functions"""
from math import radians, cos, sin, asin, sqrt
import json


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


def is_in_radius(location1, location2, radius):
    """
    Calculate the distance (km) between two points
    using the equirectangular distance approximation
    """
    lon1 = radians(float(location1['lon']))
    lat1 = radians(float(location1['lat']))
    lon2 = radians(float(location2['lon']))
    lat2 = radians(float(location2['lat']))
    # Radius of earth in kilometers. Use 3956 for miles
    return (radius / 6371)**2 >= (((lon2 - lon1) * cos(0.5*(lat2+lat1)))**2 + (lat2 - lat1)**2)


def location_encoding_func(obj):
    """Overrides the default method from the JSONEncoder"""
    if isinstance(obj, Location):
        return {'__class__': 'Location'}.update(obj.dict_representation())

    raise TypeError('Object not handled by the JSON encoding function')


class GPSLocation(object):
    """holds the coordinates"""
    lat = None
    lon = None

    def __init__(self, lat, lon):
        """init"""
        self.lat = lat
        self.lon = lon

    def is_near(self, location, radius):
        """Returns a True if the location is within the radius"""
        lon1 = radians(float(self.lon))
        lat1 = radians(float(self.lat))
        lon2 = radians(float(location.lon))
        lat2 = radians(float(location.lat))
        # Radius of earth in kilometers. Use 3956 for miles
        return (radius / 6371)**2 >= (((lon2 - lon1) * cos(0.5*(lat2+lat1)))**2 + (lat2 - lat1)**2)


class Location(GPSLocation):
    """
    A location object with the location name, coordinates and location codes
    Additionally information like the population can be saved
    """

    def __init__(self, lat, lon, city_name=None, state=None, state_code=None, population=0):
        """init"""
        self.id = None
        self.city_name = city_name
        self.state = state
        self.state_code = state_code
        self.population = population
        self.airport_info = None
        self.locode = None
        self.clli = []
        self.alternate_names = []
        super().__init__(lat, lon)

    def add_airport_info(self):
        if self.airport_info is None:
            self.airport_info = AirportInfo()

    def add_locode_info(self):
        if self.locode is None:
            self.locode = LocodeInfo()

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        airport_dict = None
        if self.airport_info:
            airport_dict = self.airport_info.dict_representation()
        locode_dict = None
        if self.locode:
            locode_dict = self.locode.dict_representation()
        return {
                'city_name': self.city_name,
                'state': self.state,
                'state_code': self.state_code,
                'population': self.population,
                'airport_info': airport_dict,
                'locode': locode_dict,
                'clli': self.clli,
                'alternate_names': self.alternate_names
        }


class AirportInfo(object):
    """Holds a list of the differen airport codes"""

    def __init__(self):
        """init"""
        self.iata_codes = []
        self.icao_codes = []
        self.faa_codes = []

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        return {
                'iata_codes': self.iata_codes,
                'icao_codes': self.icao_codes,
                'faa_codes': self.faa_codes
        }


class LocodeInfo(object):
    """Holds a list of locode codes"""

    def __init__(self):
        """init"""
        self.place_codes = []
        self.subdivision_codes = []

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        return {
                'place_codes': self.place_codes,
                'subdivision_codes': self.subdivision_codes
        }
