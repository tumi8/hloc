#!/usr/bin/env python3
"""The basic location object and all related inherited objects"""

import math

import sqlalchemy as sqla
import sqlalchemy.orm as sqlorm
from sqlalchemy.dialects import postgresql

from hloc import constants
from .sql_alchemy_base import Base
from .enums import LocationCodeType


class AirportInfo(Base):
    """Holds a list of the different airport codes"""

    __tablename__ = 'airport_infos'

    id = sqla.Column(sqla.Integer, primary_key=True)
    iata_codes = sqla.Column(postgresql.ARRAY(sqla.String(3)), default=[], nullable=False)
    icao_codes = sqla.Column(postgresql.ARRAY(sqla.String(4)), default=[], nullable=False)
    faa_codes = sqla.Column(postgresql.ARRAY(sqla.String(5)), default=[], nullable=False)

    def __init__(self):
        self.iata_codes = []
        self.icao_codes = []
        self.faa_codes = []


class LocodeInfo(Base):
    """Holds a list of locode codes"""

    __tablename__ = 'locode_infos'

    id = sqla.Column(sqla.Integer, primary_key=True)
    place_codes = sqla.Column(postgresql.ARRAY(sqla.String(6)), default=[], nullable=False)
    subdivision_codes = sqla.Column(postgresql.ARRAY(sqla.String(6)), default=[], nullable=False)

    def __init__(self):
        self.place_codes = []
        self.subdivision_codes = []

class State(Base):
    __tablename__ = 'states'

    id = sqla.Column(sqla.Integer, primary_key=True)
    name = sqla.Column(sqla.String(50), nullable=False)
    code = sqla.Column(sqla.String(5))

    location_infos = sqlorm.relationship("LocationInfo", back_populates="state")


class Location(Base):
    """
    Basic class
    just contains the coordinates
    """

    __tablename__ = 'locations'

    id = sqla.Column(sqla.Integer, primary_key=True)
    lat = sqla.Column(sqla.Float, nullable=False)
    lon = sqla.Column(sqla.Float, nullable=False)

    probes = sqlorm.relationship('Probe', back_populates='location')

    location_type = sqla.Column(sqla.String)

    __mapper_args__ = {
        'polymorphic_identity': 'location',
        'polymorphic_on': location_type
    }

    class PropertyKey:
        id = '0'
        lat = '1'
        lon = '2'

    def is_in_radius(self, location, radius):
        """Returns a True if the location is within the radius with the haversine method"""
        return self.gps_distance_haversine(location) <= radius

    def gps_distance_equirectangular(self, location):
        """Return the distance between the two locations using the equirectangular method"""
        lon1 = math.radians(float(self.lon))
        lat1 = math.radians(float(self.lat))
        lon2 = math.radians(float(location.lon))
        lat2 = math.radians(float(location.lat))

        return math.sqrt((((lon2 - lon1) * math.cos(0.5 * (lat2 + lat1))) ** 2 + (
            lat2 - lat1) ** 2)) * constants.EARTH_RADIUS

    def gps_distance_haversine(self, location2):
        """
        Calculate the distance (km) between two points
        on the earth (specified in decimal degrees)
        """
        # convert decimal degrees to radians
        lon1 = math.radians(float(self.lon))
        lat1 = math.radians(float(self.lat))
        lon2 = math.radians(float(location2.lon))
        lat2 = math.radians(float(location2.lat))
        # haversine formula
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        tmp = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
        ftmp = 2 * math.asin(math.sqrt(tmp))
        # Radius of earth in kilometers. Use 3956 for miles
        return ftmp * constants.EARTH_RADIUS

    def location_with_distance_and_bearing(self, distance: float, bearing: float):
        """
        Calculate a new Location with the distance from this location in km and in
        direction of bearing
        :param distance: the distance in km
        :param bearing: the bearing in degrees 0 is north and it goes counter clockwise
        :return: a new location in direction of bearing with the distance
        """
        bearing_rad = math.radians(bearing)
        angular_dist = distance / constants.EARTH_RADIUS
        lat_rad = math.radians(float(self.lat))
        lon_rad = math.radians(float(self.lon))

        lat_new = math.asin(math.sin(lat_rad) * math.cos(angular_dist) +
                            math.cos(lat_rad) * math.sin(angular_dist) * math.cos(bearing_rad))
        lon_new_temp = math.atan2(
            math.sin(bearing_rad) * math.sin(angular_dist) * math.cos(lat_rad),
            math.cos(angular_dist) - math.sin(lat_rad) * math.sin(lat_new))
        lon_new = ((lon_rad - lon_new_temp + math.pi) % (2 * math.pi)) - math.pi

        return math.degrees(lat_new), math.degrees(lon_new)


class LocationInfo(Location):
    """
    A location object with the location name, coordinates and location codes
    Additionally information like the population can be saved
    """

    __tablename__ = 'location_infos'

    __mapper_args__ = {'polymorphic_identity': 'location_infos'}

    id = sqla.Column(sqla.Integer, sqla.ForeignKey(Location.id), primary_key=True)
    name = sqla.Column(sqla.String(50))
    state_id = sqla.Column(sqla.Integer, sqla.ForeignKey(State.id))
    population = sqla.Column(sqla.Integer)
    airport_info_id = sqla.Column(sqla.Integer, sqla.ForeignKey(AirportInfo.id))
    locode_info_id = sqla.Column(sqla.Integer, sqla.ForeignKey(LocodeInfo.id))
    clli = sqla.Column(postgresql.ARRAY(sqla.String(6)), default=[])
    alternate_names = sqla.Column(postgresql.ARRAY(sqla.String(50)), default=[])

    state = sqlorm.relationship(State, back_populates='location_infos')
    matches = sqlorm.relationship('CodeMatch', back_populates='location_info')
    airport_info = sqlorm.relationship(AirportInfo)
    locode_info = sqlorm.relationship(LocodeInfo)

    def __init__(self, **kwargs):
        self.clli = []
        self.alternate_names = []

        for name, value in kwargs:
            setattr(self, name, value)

        super().__init__()

    def add_airport_info(self):
        """Creates and sets a new empty AirportInfo object"""
        if self.airport_info is None:
            self.airport_info = AirportInfo()

    def add_locode_info(self):
        """Creates and sets a new empty """
        if self.locode_info is None:
            self.locode_info = LocodeInfo()

    def code_id_type_tuples(self):
        """
        Creates a list with all codes in a tuple with the location id
        ONLY FOR TRIE CREATION
        :rtype: list(tuple)
        """
        # if not isinstance(self.id, int):
        #     print(self.dict_representation(), 'has no id')
        #     raise ValueError('id is not int')
        ret_list = []
        if self.name:
            ret_list.append((self.name.lower(), (self.id, LocationCodeType.geonames.value)))
        for code in self.clli:
            ret_list.append((code.lower(), (self.id, LocationCodeType.clli.value)))
        for name in self.alternate_names:
            if name:
                ret_list.append((name.lower(), (self.id, LocationCodeType.geonames.value)))
        if self.locode and self.state_code:
            for code in self.locode_info.place_codes:
                ret_list.append(('{}{}'.format(self.state_code.lower(), code.lower()),
                                 (self.id, LocationCodeType.locode.value)))
        if self.airport_info:
            for code in self.airport_info.iata_codes:
                ret_list.append((code.lower(), (self.id, LocationCodeType.iata.value)))
            for code in self.airport_info.icao_codes:
                ret_list.append((code.lower(), (self.id, LocationCodeType.icao.value)))
            for code in self.airport_info.faa_codes:
                ret_list.append((code.lower(), (self.id, LocationCodeType.faa.value)))
        return ret_list


__all__ = ['AirportInfo',
           'LocodeInfo',
           'State',
           'Location',
           'LocationInfo',
           ]
