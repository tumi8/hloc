
import enum
import logging
import math
import sys

from hloc import constants


@enum.unique
class LocationCodeType(enum.Enum):
    iata = 0
    icao = 1
    faa = 2
    clli = 3
    locode = 4
    geonames = 5

    @property
    def regex(self):
        """
        :returns the pattern for regex matching a code of the type
        :return: str
        """
        base = r'[a-zA-Z]'
        if self == LocationCodeType.iata:
            pattern = base + r'{3}'
        elif self == LocationCodeType.icao:
            pattern = base + r'{4}'
        elif self == LocationCodeType.clli:
            pattern = base + r'{6}'
        elif self == LocationCodeType.locode:
            pattern = base + r'{5}'
        elif self == LocationCodeType.geonames:
            pattern = r'[a-zA-Z]+'
        else:
            logging.error('WTF? should not be possible')
            return

        return r'(?P<type>' + pattern + r')'


class GPSLocation(object):
    """holds the coordinates"""

    class_name_identifier = 'gl'

    __slots__ = ['_id', 'lat', 'lon']

    class PropertyKey:
        id = '0'
        lat = '1'
        lon = '2'

    def __init__(self, lat, lon):
        """init"""
        self._id = None
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
            logging.critical('Error: GPSLocation.id must be an Integer!', file=sys.stderr)
            raise

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
        angular_dist = distance/constants.EARTH_RADIUS
        lat_rad = math.radians(float(self.lat))
        lon_rad = math.radians(float(self.lon))

        lat_new = math.asin(math.sin(lat_rad)*math.cos(angular_dist) +
                            math.cos(lat_rad)*math.sin(angular_dist)*math.cos(bearing_rad))
        lon_new_temp = math.atan2(
            math.sin(bearing_rad)*math.sin(angular_dist)*math.cos(lat_rad),
            math.cos(angular_dist)-math.sin(lat_rad)*math.sin(lat_new))
        lon_new = ((lon_rad - lon_new_temp + math.pi) % (2*math.pi)) - math.pi

        return GPSLocation(math.degrees(lat_new), math.degrees(lon_new))

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        ret_dict = {
            constants.JSON_CLASS_IDENTIFIER: self.class_name_identifier,
            GPSLocation.PropertyKey.lat: self.lat,
            GPSLocation.PropertyKey.lon: self.lon
        }
        if self.id is not None:
            ret_dict[GPSLocation.PropertyKey.id] = self.id

        return ret_dict

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a Location object from a dictionary"""
        obj = GPSLocation(dct[GPSLocation.PropertyKey.lat], dct[GPSLocation.PropertyKey.lon])
        if GPSLocation.PropertyKey.id in dct:
            obj.id = dct[GPSLocation.PropertyKey.id]
        return obj

    def copy(self):
        obj = GPSLocation(self.lat, self.lon)
        obj.id = self.id
        return obj


class Location(GPSLocation):
    """
    A location object with the location name, coordinates and location codes
    Additionally information like the population can be saved
    """

    class_name_identifier = 'loc'

    __slots__ = ['lat', 'lon', 'city_name', 'state', 'state_code', 'population',
                 'airport_info', 'locode', 'clli', 'alternate_names', 'nodes',
                 'available_nodes', 'has_probeapi']

    class PropertyKey:
        city_name = '3'
        state = '4'
        state_code = '5'
        population = '6'
        clli = '7'
        alternate_names = '8'
        airport_info = '9'
        locode = 'a'
        nodes = 'b'
        available_nodes = 'c'
        has_probeapi = 'd'

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
        self.has_probeapi = []
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
        del ret_dict[constants.JSON_CLASS_IDENTIFIER]
        ret_dict.update({
            constants.JSON_CLASS_IDENTIFIER: self.class_name_identifier,
            self.PropertyKey.city_name: self.city_name,
            self.PropertyKey.state: self.state,
            self.PropertyKey.state_code: self.state_code,
            self.PropertyKey.population: self.population,
            self.PropertyKey.clli: self.clli,
            self.PropertyKey.alternate_names: self.alternate_names,
        })
        if self.airport_info:
            ret_dict[self.PropertyKey.airport_info] = self.airport_info.dict_representation()

        if self.locode:
            ret_dict[self.PropertyKey.locode] = self.locode.dict_representation()

        if self.available_nodes:
            ret_dict[self.PropertyKey.available_nodes] = self.available_nodes

        if self.nodes:
            ret_dict[self.PropertyKey.nodes] = self.nodes

        if self.has_probeapi:
            ret_dict[self.PropertyKey.has_probeapi] = [loc.dict_representation()
                                                       for loc in self.has_probeapi]

        return ret_dict

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
        if self.city_name:
            ret_list.append((self.city_name.lower(), (self.id, LocationCodeType.geonames.value)))
        for code in self.clli:
            ret_list.append((code.lower(), (self.id, LocationCodeType.clli.value)))
        for name in self.alternate_names:
            if name:
                ret_list.append((name.lower(), (self.id, LocationCodeType.geonames.value)))
        if self.locode and self.state_code:
            for code in self.locode.place_codes:
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

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a Location object from a dictionary"""
        obj = Location(dct[GPSLocation.PropertyKey.lat], dct[GPSLocation.PropertyKey.lon],
                       dct[Location.PropertyKey.city_name], dct[Location.PropertyKey.state],
                       dct[Location.PropertyKey.state_code], dct[Location.PropertyKey.population])

        if Location.PropertyKey.clli in dct:
            obj.clli = dct[Location.PropertyKey.clli]
        if Location.PropertyKey.alternate_names in dct:
            obj.alternate_names = dct[Location.PropertyKey.alternate_names]
        if GPSLocation.PropertyKey.id in dct:
            obj.id = dct[GPSLocation.PropertyKey.id]
        if Location.PropertyKey.airport_info in dct:
            obj.airport_info = dct[Location.PropertyKey.airport_info]
        if Location.PropertyKey.locode in dct:
            obj.locode = dct[Location.PropertyKey.locode]
        if Location.PropertyKey.available_nodes in dct:
            obj.available_nodes = dct[Location.PropertyKey.available_nodes]
        if Location.PropertyKey.nodes in dct:
            obj.nodes = dct[Location.PropertyKey.nodes]
        if Location.PropertyKey.has_probeapi in dct:
            obj.has_probeapi = dct[Location.PropertyKey.has_probeapi]
        return obj

    def copy(self):
        obj = Location(self.lat, self.lon, self.city_name, self.state, self.state_code,
                       self.population)
        obj.id = self.id
        obj.clli = self.clli
        obj.airport_info = self.airport_info.copy()
        obj.locode = self.locode.copy()
        obj.available_nodes = self.available_nodes.copy()
        obj.nodes = self.nodes.copy()
        return obj


class AirportInfo(object):
    """Holds a list of the different airport codes"""

    class_name_identifier = 'ai'

    __slots__ = ['iata_codes', 'icao_codes', 'faa_codes']

    class PropertyKey:
        iata_codes = '0'
        icao_codes = '1'
        faa_codes = '2'

    def __init__(self):
        """init"""
        self.iata_codes = []
        self.icao_codes = []
        self.faa_codes = []

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        return {
            constants.JSON_CLASS_IDENTIFIER: self.class_name_identifier,
            self.PropertyKey.iata_codes: self.iata_codes,
            self.PropertyKey.icao_codes: self.icao_codes,
            self.PropertyKey.faa_codes: self.faa_codes
        }

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a AirportInfo object from a dictionary"""
        obj = AirportInfo()
        obj.faa_codes = dct[AirportInfo.PropertyKey.faa_codes]
        obj.iata_codes = dct[AirportInfo.PropertyKey.iata_codes]
        obj.icao_codes = dct[AirportInfo.PropertyKey.icao_codes]
        return obj

    def copy(self):
        obj = AirportInfo()
        obj.faa_codes = self.faa_codes[:]
        obj.icao_codes = self.icao_codes[:]
        obj.iata_codes = self.iata_codes[:]
        return obj


class LocodeInfo(object):
    """Holds a list of locode codes"""

    class_name_identifier = 'li'

    __slots__ = ['place_codes', 'subdivision_codes']

    class PropertyKey:
        place_codes = '0'
        subdivision_codes = '1'

    def __init__(self):
        """init"""
        self.place_codes = []
        self.subdivision_codes = []

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        return {
            constants.JSON_CLASS_IDENTIFIER: self.class_name_identifier,
            self.PropertyKey.place_codes: self.place_codes,
            self.PropertyKey.subdivision_codes: self.subdivision_codes
        }

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a LocodeInfo object from a dictionary"""
        obj = LocodeInfo()
        obj.place_codes = dct[LocodeInfo.PropertyKey.place_codes]
        obj.subdivision_codes = dct[LocodeInfo.PropertyKey.subdivision_codes]
        return obj

    def copy(self):
        obj = LocodeInfo()
        obj.place_codes = self.place_codes[:]
        obj.subdivision_codes = self.subdivision_codes[:]
        return obj

__all__ = ['Location',
           'GPSLocation',
           'LocationCodeType',
           'AirportInfo',
           'LocodeInfo'
           ]