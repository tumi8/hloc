#!/usr/bin/env python3

"""
 * All Probe classes used by the HLOC framework
"""

import datetime
import logging
import random
import time
import enum
import typing
import multiprocessing as mp

import ripe.atlas.cousteau as ripe_atlas
import sqlalchemy as sqla
import sqlalchemy.orm as sqlorm

from hloc import util, constants
from .location import probe_location_info_table
from .sql_alchemy_base import Base
from hloc.ripe_helper import get_ripe_measurement
from hloc.exceptions import ProbeError
from hloc.models import Session, Location, RipeMeasurementResult, AvailableType


class Probe(Base):
    """
    The abstract base class for a Probe used by the HLOC library
    Cannot use metaclass = abc.MetaClass because of sqlAlchemy
    """

    __tablename__ = 'probes'

    id = sqla.Column(sqla.Integer, primary_key=True)
    probe_id = sqla.Column(sqla.String(30), nullable=False)
    location_id = sqla.Column(sqla.Integer, sqla.ForeignKey(Location.id), nullable=False)
    last_seen = sqla.Column(sqla.DateTime)

    location = sqlorm.relationship(Location, back_populates='probes')
    location_infos = sqlorm.relationship('LocationInfo',
                                         secondary=probe_location_info_table,
                                         back_populates="nearby_probes")
    measurements = sqlorm.relationship('MeasurementResult', back_populates='probe')

    measurement_type = sqla.Column(sqla.String)

    __mapper_args__ = {'polymorphic_on': measurement_type}

    def measure_rtt(self, dest_address, db_session, **kwargs):
        """Creates a method for the Probe"""
        raise NotImplementedError("subclass must implement this")

    @property
    def last_update(self):
        """return timestamp when the probe was last updated"""
        raise NotImplementedError("subclass must implement this")

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

    required_keys = ['measurement_name', 'ip_version', 'api_key', 'ripe_slowdown_sema']

    class MeasurementKeys(enum.Enum):
        measurement_name = 'measurement_name'
        ip_version = 'ip_version'
        num_packets = 'num_packets'
        api_key = 'api_key'
        bill_to_address = 'bill_to_address'
        ripe_slowdown_sema = 'ripe_slowdown_sema'

        @staticmethod
        def get_default_for(property_key) -> typing.Any:
            if property_key == RipeAtlasProbe.MeasurementKeys.Num_packets:
                return 1
            elif property_key == RipeAtlasProbe.MeasurementKeys.Bill_to_address:
                return None
            raise ValueError('Property ' + property_key + ' has no default value')

    def __init__(self, **kwargs):
        self._last_update = None
        self._probe_obj = None

        for name, value in kwargs.items():
            setattr(self, name, value)

        super().__init__()

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

    def measure_rtt(self, dest_address: str, db_session: Session, **kwargs) -> typing.Optional[RipeMeasurementResult]:
        if not self.available:
            # TODO use own errors
            raise ValueError('Probe currently not available')

        for prop_key in util.get_class_properties(RipeAtlasProbe.MeasurementKeys):
            key = RipeAtlasProbe.MeasurementKeys().__getattribute__(prop_key)
            if key not in kwargs:
                if key in self.required_keys:
                    raise ValueError('Could not find required argument ' + key +
                                     ' for creating a Ripe Atlas measurement')
                else:
                    kwargs[key] = RipeAtlasProbe.MeasurementKeys.get_default_for(key)

        ripe_slowdown_sema = kwargs.pop(RipeAtlasProbe.MeasurementKeys().Ripe_Slowdown_Sema)

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
        measurement_id = response['measurements'][0]

        if measurement_id is None:
            return None

        measurement_result = self._get_measurement_response(measurement_id,
                                                            ripe_slowdown_sema=ripe_slowdown_sema)
        db_session.add(measurement_result)
        return measurement_result

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

    def _get_measurement_response(self, measurement_id: int, ripe_slowdown_sema: mp.Semaphore) -> \
            RipeMeasurementResult:

        def sleep_time(amount: float = 10):
            """Sleep for ten seconds"""
            time.sleep(amount)

        sleep_time(amount=360)
        while True:
            res = get_ripe_measurement(measurement_id)
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

        measurement_result = RipeMeasurementResult.create_from_dict(m_results[0])
        measurement_result.probe = self
        return measurement_result

    @property
    def last_update(self):
        """return timestamp when the probe was last updated"""
        return self._last_update

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


__all__ = ['Probe',
           'RipeAtlasProbe',
           ]
