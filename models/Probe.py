#!/usr/bin/env python3

"""
 * All Probe classes used by the HLOC framework
"""

import abc
from . import MeasurementResult
from .. import util
import typing
import datetime
import ripe.atlas.cousteau as ripe_atlas
import logging
import random
import time
import enum


class Probe(metaclass=abc.ABCMeta):
    """The abstract base class for a Probe used by the HLOC library"""

    @abc.abstractmethod
    def measure_rtt(self, dest_address, **kwargs) -> typing.Optional[MeasurementResult]:
        """Creates a method for the Probe"""
        pass

    @property
    @abc.abstractmethod
    def location(self) -> typing.Optional[util.GPSLocation]:
        pass

    @property
    @abc.abstractmethod
    def last_update(self) -> typing.Optional[datetime.datetime]:
        """return timestamp when the probe was last updated"""
        pass

    @property
    @abc.abstractmethod
    def available(self, max_age: datetime.timedelta) -> AvailableType:
        """Should return if the probe is available for measurements"""
        pass

    @property
    @abc.abstractmethod
    def ipv6_capable(self) -> bool:
        """Should return if the probe is capable of performing ipv6 measurements"""
        pass

    @abc.abstractmethod
    def __init__(self, json_dict):
        """creates a new object out of the json dictionary retrieved from the service"""
        pass


@enum.unique
class AvailableType(enum.Enum):
    available = '0'
    not_available = '1'
    unknown = '2'


class RipeAtlasProbe():
    """a representation of the ripe atlas probe"""

    __slots__ = ['_id', '_location', '_last_update', '_available']

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
        def get_default_for(property):
            if property == RipeAtlasProbe.MeasurementKeys.Num_packets:
                return 1
            raise ValueError('Property ' + property + ' has no default value')

    def __init__(self, json_dict):
        if RipeAtlasProbe.JsonKeys.Id_key in json_dict:
            self._id = json_dict[RipeAtlasProbe.JsonKeys.Id_key]
        else:
            ValueError('id not in json to create Ripe Atlas Probe object')

        if RipeAtlasProbe.JsonKeys.Lat_key in json_dict and \
                        RipeAtlasProbe.JsonKeys.Lon_key in json_dict:
            self._location = util.GPSLocation(json_dict[RipeAtlasProbe.JsonKeys.Lat_key],
                                              json_dict[RipeAtlasProbe.JsonKeys.Lon_key])
        else:
            ValueError('latitude or longitude not in json to create Ripe Atlas Probe object')

        self._last_update = datetime.datetime.now()
        self._available = AvailableType.unknown

    def measure_rtt(self, dest_address, **kwargs) -> typing.Optional[MeasurementResult]:
        for key in util.get_class_properties(RipeAtlasProbe.MeasurementKeys):
            if key not in kwargs:
                if key in self.required_keys:
                    raise ValueError('Could not find required argumen ' + key +
                                     ' for creating a Ripe Atlas measurement')
                else:
                    kwargs[key] = RipeAtlasProbe.MeasurementKeys.get_default_for(key)

        if kwargs[RipeAtlasProbe.MeasurementKeys.IP_version] == util.IPV4_IDENTIFIER:
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

        atlas_request = ripe_atlas.AtlasCreateRequest(**atlas_request_args)

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

    @property
    def location(self) -> typing.Optional[util.GPSLocation]:
        return self._location

    @property
    def last_update(self) -> typing.Optional[datetime.datetime]:
        """return timestamp when the probe was last updated"""
        return self._last_update

    @property
    def available(self, max_age=datetime.timedelta(hours=12)) -> AvailableType:
        """
        Should return if the probe is available for measurements
        :param max_age datetime.timedelta: the maximum age of the info
        """
        if datetime.datetime.now() - max_age <= self._last_update:
            return self._available
        else:
            source = ripe_atlas.ProbeRequest(value=self._id, requested=1, type='probes')

    @property
    def ipv6_capable(self) -> bool:
        """Should return if the probe is capable of performing ipv6 measurements"""
        pass


Probe.register(RipeAtlasProbe)
