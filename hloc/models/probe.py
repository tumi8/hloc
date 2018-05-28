#!/usr/bin/env python3

"""
 * All Probe classes used by the HLOC framework
"""

import datetime
import enum
import logging
import multiprocessing as mp
import operator
import random
import time
import typing

import ripe.atlas.cousteau as ripe_atlas
import sqlalchemy as sqla
import sqlalchemy.orm as sqlorm

import hloc.ripe_helper.basics_helper as ripe_helper
from hloc import util, constants
from hloc.constants import IPV6_IDENTIFIER, IPV4_IDENTIFIER
from hloc.exceptions import ProbeError, MeasurementError
from hloc.models import Location, RipeMeasurementResult, AvailableType, Base
from .location import probe_location_info_table


class Probe(Base):
    """
    The abstract base class for a Probe used by the HLOC library
    Cannot use metaclass = abc.MetaClass because of sqlAlchemy
    """

    __tablename__ = 'probes'

    id = sqla.Column(sqla.Integer, primary_key=True)
    probe_id = sqla.Column(sqla.String(100), nullable=False)
    location_id = sqla.Column(sqla.String(32), sqla.ForeignKey(Location.id), nullable=False)
    last_seen = sqla.Column(sqla.DateTime)

    location = sqlorm.relationship(Location, back_populates='probes', cascade='all')
    location_infos = sqlorm.relationship('LocationInfo',
                                         secondary=probe_location_info_table,
                                         back_populates="nearby_probes")
    measurements = sqlorm.relationship('MeasurementResult', back_populates='probe')

    measurement_type = sqla.Column(sqla.String)

    __mapper_args__ = {'polymorphic_on': measurement_type}

    def measure_rtt(self, dest_address, **kwargs):
        """Creates a method for the Probe"""
        raise NotImplementedError("subclass must implement this")

    @property
    def last_update(self) -> datetime.datetime:
        """return timestamp when the probe was last updated"""
        raise NotImplementedError("subclass must implement this")

    def available(self, max_age: datetime.timedelta) -> AvailableType:
        """Should return if the probe is available for measurements"""
        raise NotImplementedError("subclass must implement this")

    def is_available(self, max_age: datetime.timedelta) -> bool:
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

    def __hash__(self):
        return hash(self.probe_id)


class RipeAtlasProbe(Probe):
    """a representation of the ripe atlas probe"""

    __RIPE_ATLAS_LOCATION_OBFUSCATION_RADIUS__ = 30

    second_hop_latency = sqla.Column(sqla.Float)

    __mapper_args__ = {'polymorphic_identity': 'ripe_atlas'}

    required_keys = ['measurement_name', 'ip_version', 'api_key', 'ripe_slowdown_sema']

    _last_update = None
    _probe_obj = None

    class MeasurementKeys(enum.Enum):
        measurement_name = 'measurement_name'
        ip_version = 'ip_version'
        num_packets = 'num_packets'
        api_key = 'api_key'
        bill_to_address = 'bill_to_address'
        ripe_slowdown_sema = 'ripe_slowdown_sema'
        tags = 'tags'

        additional_probes = 'additional_probes'

        @staticmethod
        def get_default_for(property_key: str) -> typing.Any:
            if property_key == RipeAtlasProbe.MeasurementKeys.num_packets.value:
                return 1
            elif property_key == RipeAtlasProbe.MeasurementKeys.bill_to_address.value:
                return None
            elif property_key == RipeAtlasProbe.MeasurementKeys.additional_probes.value:
                return []
            raise ValueError('Property ' + property_key + ' has no default value')

    def __init__(self, **kwargs):
        self._last_update = None
        self._probe_obj = None

        for name, value in kwargs.items():
            setattr(self, name, value)

        super().__init__()

    @staticmethod
    def parse_from_json(json_dict) -> 'RipeAtlasProbe':
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
        probe.probe_id = str(_id)
        probe.location = _location
        probe._update()

        return probe

    def measure_rtt(self, dest_address: str, **kwargs) \
            -> typing.Optional[RipeMeasurementResult]:
        if not self.available:
            raise ProbeError('Probe currently not available')

        for prop_key in util.get_class_properties(RipeAtlasProbe.MeasurementKeys):
            if prop_key in ['name', 'value']:
                continue

            key = RipeAtlasProbe.MeasurementKeys(prop_key).value
            if key not in kwargs:
                if key in self.required_keys:
                    raise ValueError('Could not find required argument ' +
                                     RipeAtlasProbe.MeasurementKeys(key).value +
                                     ' for creating a Ripe Atlas measurement')
                else:
                    kwargs[key] = RipeAtlasProbe.MeasurementKeys.get_default_for(key)

        ripe_slowdown_sema = kwargs.pop(RipeAtlasProbe.MeasurementKeys.ripe_slowdown_sema.value)

        atlas_request = self._create_request(dest_address, kwargs)

        ripe_slowdown_sema.acquire()
        (success, response) = atlas_request.create()

        retries = 0
        while not success:
            ripe_slowdown_sema.acquire()
            success, response = atlas_request.create()

            if success:
                break

            if isinstance(response, dict):
                if response.get('status', 0) >= 400 and \
                        'start time in future' not in \
                        response.get('errors', [{}])[0].get('detail', ''):
                    # If "start time in future" is in the error message then we assume it is a
                    # RA problem as we do not send a start time.
                    raise MeasurementError(response)
            retries += 1
            time.sleep(10 + (random.randrange(0, 500) / 100) * retries)

            if retries % 5 == 0:
                logging.error('Create error {}'.format(response))

        measurement_id = response['measurements'][0]

        if measurement_id is None:
            return None

        additional_probes = kwargs.get(RipeAtlasProbe.MeasurementKeys.additional_probes.value, [])
        measurement_result = self._get_measurement_response(measurement_id,
                                                            ripe_slowdown_sema=ripe_slowdown_sema,
                                                            additional_probes=additional_probes)
        return measurement_result

    def _create_request(self, dest_address, kwargs):
        """Creates a Ripe atlas request out of the arguments"""
        if kwargs[RipeAtlasProbe.MeasurementKeys.ip_version.value] == constants.IPV4_IDENTIFIER:
            af = 4
        else:
            af = 6

        packets = kwargs[RipeAtlasProbe.MeasurementKeys.num_packets.value]
        measurement_description = kwargs[RipeAtlasProbe.MeasurementKeys.measurement_name.value]
        tags = kwargs.get(RipeAtlasProbe.MeasurementKeys.tags.value, [])

        ping = ripe_atlas.Ping(af=af, packets=packets, target=dest_address,
                               description=measurement_description, tags=tags)

        if RipeAtlasProbe.MeasurementKeys.additional_probes.value in kwargs:
            probe_ids = [str(self.probe_id)]
            for probe in kwargs[RipeAtlasProbe.MeasurementKeys.additional_probes.value]:
                probe_ids.append(str(probe.probe_id))

            source = ripe_atlas.AtlasSource(value=','.join(probe_ids), requested=1, type='probes')
        else:
            source = ripe_atlas.AtlasSource(value=self.probe_id, requested=1, type='probes')

        # unix_timestamp = int(datetime.datetime.now().timestamp())

        atlas_request_args = {
            'key': kwargs[RipeAtlasProbe.MeasurementKeys.api_key.value],
            'measurements': [ping],
            'sources': [source],
            'is_oneoff': True,
            'verify': kwargs.get('verify', True)
        }

        if RipeAtlasProbe.MeasurementKeys.bill_to_address.value in kwargs:
            atlas_request_args['bill_to'] = kwargs[
                RipeAtlasProbe.MeasurementKeys.bill_to_address.value]

        return ripe_atlas.AtlasCreateRequest(**atlas_request_args)

    def _get_measurement_response(self, measurement_id: int, ripe_slowdown_sema: mp.Semaphore,
                                  additional_probes: ['RipeAtlasProbe']) \
            -> typing.Optional[RipeMeasurementResult]:
        def sleep_time(amount: float = 10):
            """Sleep for ten seconds"""
            time.sleep(amount)

        sleep_time(amount=360)
        while True:
            ripe_slowdown_sema.acquire()
            res = ripe_helper.get_ripe_measurement(measurement_id)
            if res is not None:
                if res.status_id == 4:
                    break
                elif res.status_id in [6, 7]:
                    raise ProbeError()
                elif res.status_id in [0, 1, 2]:
                    sleep_time()
            else:
                sleep_time()

        ripe_slowdown_sema.acquire()
        success, m_results = ripe_atlas.AtlasResultsRequest(
            **{'msm_id': measurement_id}).create()
        while not success:
            logging.error('ResultRequest error {}'.format(m_results))
            sleep_time(amount=(10 + (random.randrange(0, 500) / 100)))
            ripe_slowdown_sema.acquire()
            success, m_results = ripe_atlas.AtlasResultsRequest(
                **{'msm_id': measurement_id}).create()

        if not m_results or not isinstance(m_results, list):
            return None

        min_result = min(m_results, key=operator.itemgetter('min'))
        measurement_result = RipeMeasurementResult.create_from_dict(min_result)
        if self.probe_id == str(min_result['prb_id']):
            measurement_result.probe_id = self.id
        else:
            probe = [probe for probe in additional_probes
                     if probe.probe_id == str(min_result['prb_id'])][0]
            measurement_result.probe_id = probe.id

        return measurement_result

    @property
    def last_update(self):
        """return timestamp when the probe was last updated"""
        return self._last_update

    def available(self, max_age=datetime.timedelta(hours=2)) -> typing.Optional[AvailableType]:
        """
        Should return if the probe is available for measurements
        :param max_age: :datetime.timedelta: the maximum age of the info
        """
        if not self._last_update or datetime.datetime.now() - max_age >= self._last_update:
            if not self._update():
                if self._probe_obj:
                    raise ProbeError('Probes location changed')
                raise ProbeError('Probe object could not be fetched')

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

    def is_available(self, ip_version: typing.Optional[str], max_age=datetime.timedelta(hours=12)) \
            -> bool:
        if not ip_version:
            return self.available(max_age=max_age) == AvailableType.both_available

        if ip_version == IPV4_IDENTIFIER:
            return self.available(max_age=max_age) in [AvailableType.both_available,
                                                       AvailableType.ipv4_available]
        if ip_version == IPV6_IDENTIFIER:
            return self.available(max_age=max_age) in [AvailableType.both_available,
                                                       AvailableType.ipv6_available]
        raise ValueError('ip version string not recognized')

    @property
    def ipv6_capable(self) -> bool:
        """Should return if the probe is capable of performing ipv6 measurements"""
        if not self._probe_obj:
            if not self._update():
                raise ProbeError('probe could not be fetched')
        return 'system-ipv6-capable' in [tag['slug'] for tag in self._probe_obj.tags]

    def update(self) -> bool:
        return self._update()

    def _update(self) -> bool:
        """Updates the probes status"""
        self._probe_obj = ripe_atlas.Probe(id=self.probe_id)
        self._last_update = datetime.datetime.now()

        if not self._probe_obj.geometry:
            logging.debug('no geometry found for ripe atlas id %s', self.probe_id)
            return False

        new_lat = self._probe_obj.geometry['coordinates'][1]
        new_lon = self._probe_obj.geometry['coordinates'][0]

        is_near = self.is_near(new_lat, new_lon)
        if not is_near:
            logging.debug('ripe atlas probe %s (db %s) is now at %s, %s', self.probe_id, self.id,
                          new_lat, new_lon)

        return is_near

    def is_near(self, lat, lon):
        distance = self.location.gps_distance_haversine_plain(lat, lon)
        return abs(distance) < self.__RIPE_ATLAS_LOCATION_OBFUSCATION_RADIUS__

    def is_rfc_1918(self) -> bool:
        """Returns if the probe is behind a NAT according to RFC 1918"""
        if not self._probe_obj:
            if not self._update():
                raise ProbeError('probe could not be fetched')
        return 'system-ipv4-rfc1918' in [tag['slug'] for tag in self._probe_obj.tags]


class CaidaArkProbe(Probe):

    __mapper_args__ = {'polymorphic_identity': 'caida_ark'}

    def measure_rtt(self, dest_address, **kwargs):
        raise NotImplementedError('Caida Results are only gathered passively')

    @property
    def last_update(self) -> datetime.datetime:
        raise NotImplementedError("Caida Probes are passive")

    def available(self, max_age: datetime.timedelta) -> AvailableType:
        return AvailableType.unknown

    def is_available(self, max_age: datetime.timedelta) -> bool:
        return False

    @property
    def ipv6_capable(self) -> bool:
        return False

    @staticmethod
    def parse_from_json(json_dict) -> typing.Optional['CaidaArkProbe']:
        return None


class ZmapProbe(Probe):

    __mapper_args__ = {'polymorphic_identity': 'zmap'}

    def measure_rtt(self, dest_address, **kwargs):
        raise NotImplementedError('Zmap Results are only gathered passively')

    @property
    def last_update(self) -> datetime.datetime:
        raise NotImplementedError("Zmap Probes are passive")

    def available(self, max_age: datetime.timedelta) -> AvailableType:
        return AvailableType.unknown

    def is_available(self, max_age: datetime.timedelta) -> bool:
        return False

    @property
    def ipv6_capable(self) -> bool:
        return False

    @staticmethod
    def parse_from_json(json_dict) -> typing.Optional['ZmapProbe']:
        return None


__all__ = ['Probe',
           'RipeAtlasProbe',
           'CaidaArkProbe',
           'ZmapProbe',
           ]
