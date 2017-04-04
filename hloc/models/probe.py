#!/usr/bin/env python3

"""
 * All Probe classes used by the HLOC framework
"""

import datetime
import logging
import random
import time

import ripe.atlas.cousteau as ripe_atlas
import sqlalchemy as sqla
import sqlalchemy.orm as sqlorm

from hloc import util, constants
from .location import Location
from .sql_alchemy_base import Base
from .enums import AvailableType


class Probe(Base):
    """
    The abstract base class for a Probe used by the HLOC library
    Cannot use metaclass = abc.MetaClass because of sqlAlchemy
    """

    __tablename__ = 'probes'

    id = sqla.Column(sqla.Integer, primary_key=True)
    probe_id = sqla.Column(sqla.String(30))
    location_id = sqla.Column(sqla.Integer, sqla.ForeignKey(Location.id))
    location = sqlorm.relationship(Location, back_populates='probes')
    last_seen = sqla.Column(sqla.DateTime)

    measurements = sqlorm.relationship('MeasurementResult', back_populates='probe')

    measurement_type = sqla.Column(sqla.String)

    __mapper_args__ = {'polymorphic_on': measurement_type}

    def measure_rtt(self, dest_address, **kwargs):
        """Creates a method for the Probe"""
        raise NotImplementedError("subclass must implement this")

    @property
    def last_update(self):
        """return timestamp when the probe was last updated"""
        raise NotImplementedError("subclass must implement this")

    @property
    def available(self, max_age: datetime.timedelta) -> AvailableType:
        """Should return if the probe is available for measurements"""
        raise NotImplementedError("subclass must implement this")

    @property
    def ipv6_capable(self) -> bool:
        """Should return if the probe is capable of performing ipv6 measurements"""
        raise NotImplementedError("subclass must implement this")

    @staticmethod
    def parse_from_json(json_dict):
        """
        creates a new object out of the json dictionary retrieved from the service
        :returns The according probe object or None if it could not be parsed
        """
        raise NotImplementedError("subclass must implement this")

    def __repr__(self):
        return "<Probe(id: " + str(self.id) + ", probe_id: " + str(self.probe_id) + \
               ", location_id: " + str(self.location_id) + ", last_seen: " + str(self.last_seen) + \
               ", last_seen: " + str(self.last_seen) + ", measurement_type: " + \
               self.measurement_type + ")>"


class RipeAtlasProbe(Probe):
    """a representation of the ripe atlas probe"""

    __mapper_args__ = {'polymorphic_identity': 'ripe_atlas'}

    __slots__ = ['_last_update', '_probe_obj']

    class JsonKeys:
        Id_key = 'id'
        Lat_key = 'latitude'
        Lon_key = 'longitude'

    required_keys = ['Measurement_name', 'IP_version', 'Api_key', 'Create_semaphore']

    class MeasurementKeys:

        Measurement_name = 'measurement_name'
        IP_version = 'ip_version'
        Num_packets = 'num_packets'
        Api_key = 'api_key'
        Bill_to_address = 'bill_to_address'
        Create_semaphore = 'create_sema'

        @staticmethod
        def get_default_for(property_key):
            if property_key == RipeAtlasProbe.MeasurementKeys.Num_packets:
                return 1
            raise ValueError('Property ' + property_key + ' has no default value')

    @staticmethod
    def parse_from_json(json_dict):
        _id = None
        _location = None
        if RipeAtlasProbe.JsonKeys.Id_key in json_dict:
            _id = json_dict[RipeAtlasProbe.JsonKeys.Id_key]
        else:
            ValueError('id not in json to create Ripe Atlas Probe object')

        if RipeAtlasProbe.JsonKeys.Lat_key in json_dict and \
                RipeAtlasProbe.JsonKeys.Lon_key in json_dict:
            _location = Location(json_dict[RipeAtlasProbe.JsonKeys.Lat_key],
                                      json_dict[RipeAtlasProbe.JsonKeys.Lon_key])
        else:
            ValueError('latitude or longitude not in json to create Ripe Atlas Probe object')

        probe = RipeAtlasProbe()
        probe.id = _id
        probe.location = _location
        probe._update()

    def measure_rtt(self, dest_address, **kwargs):
        if not self.available:
            raise ValueError('Probe currently not available')
        for prop_key in util.get_class_properties(RipeAtlasProbe.MeasurementKeys):
            key = RipeAtlasProbe.MeasurementKeys().__getattribute__(prop_key)
            if key not in kwargs:
                if key in self.required_keys:
                    raise ValueError('Could not find required argument ' + key +
                                     ' for creating a Ripe Atlas measurement')
                else:
                    kwargs[key] = RipeAtlasProbe.MeasurementKeys.get_default_for(key)

        atlas_request = self._create_request(dest_address, kwargs)

        (success, response) = atlas_request.create()

        retries = 0
        while not success:
            success, response = atlas_request.create()

            if success:
                break
            time.sleep(10 + (random.randrange(0, 500) / 100))

            retries += 1
            if retries % 5 == 0:
                logging.error('Create error {}'.format(response))

        # TODO create lazy measurement result which waits until response is available
        measurement_ids = response['measurements']
        return measurement_ids[0]

    def _create_request(self, dest_address, kwargs):
        """Creates a Ripe atlas request out of the arguments"""
        if kwargs[RipeAtlasProbe.MeasurementKeys.IP_version] == constants.IPV4_IDENTIFIER:
            af = 4
        else:
            af = 6

        packets = kwargs[RipeAtlasProbe.MeasurementKeys.Num_packets]
        measurement_description = kwargs[RipeAtlasProbe.MeasurementKeys.Measurement_name]

        ping = ripe_atlas.Ping(af=af, packets=packets, target=dest_address,
                               description=measurement_description)
        source = ripe_atlas.AtlasSource(value=self._id, requested=1, type='probes')

        atlas_request_args = {
            'key': kwargs[RipeAtlasProbe.MeasurementKeys.Api_key],
            'measurements': [ping],
            'sources': [source],
            'is_oneoff': True
        }
        if RipeAtlasProbe.MeasurementKeys.Bill_to_address in kwargs:
            atlas_request_args['bill_to'] = kwargs[RipeAtlasProbe.MeasurementKeys.Bill_to_address]

        return ripe_atlas.AtlasCreateRequest(**atlas_request_args)

    @property
    def last_update(self):
        """return timestamp when the probe was last updated"""
        return self._last_update

    @property
    def available(self, max_age=datetime.timedelta(hours=12)) -> AvailableType:
        """
        Should return if the probe is available for measurements
        :param max_age: :datetime.timedelta: the maximum age of the info
        """
        if datetime.datetime.now() - max_age >= self._last_update:
            self._update()

        if not self._probe_obj:
            return AvailableType.unknown

        available = AvailableType.not_available
        if self._probe_obj.status == 'Connected' and \
                'system-ipv4-works' in [tag['slug'] for tag in self._probe_obj.tags] and \
                'system-ipv4-capable' in [tag['slug'] for tag in self._probe_obj.tags]:
            available = AvailableType.ipv4_available

        if self._probe_obj.status == 'Connected' and \
                'system-ipv6-works' in [tag['slug'] for tag in self._probe_obj.tags] and \
                'system-ipv6-capable' in [tag['slug'] for tag in self._probe_obj.tags]:
            if available == AvailableType.ipv4_available:
                available = AvailableType.both_available
            else:
                available = AvailableType.ipv6_available

        return available

    @property
    def ipv6_capable(self) -> bool:
        """Should return if the probe is capable of performing ipv6 measurements"""
        if not self._probe_obj:
            self._update()
        return 'system-ipv6-capable' in [tag['slug'] for tag in self._probe_obj.tags]

    def _update(self):
        """Updates the probes status"""
        self._probe_obj = ripe_atlas.Probe(id=self._id)
        self._last_update = datetime.datetime.now()
