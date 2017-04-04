#!/usr/bin/env python3
"""
 * All measurement result classes used by the HLOC framework
"""

import sqlalchemy as sqla
import sqlalchemy.orm as sqlorm
from sqlalchemy.dialects import postgresql
from hloc.models.sql_alchemy_base import Base

from hloc import constants
from .enums import MeasurementError


class MeasurementResult(Base):
    """the abstract base class for a measurement result"""

    __tablename__ = 'measurement_results'

    id = sqla.Column(sqla.Integer, primary_key=True)
    platform_id = sqla.Column(sqla.Integer)
    probe_id = sqla.Column(sqla.Integer, sqla.ForeignKey('probes.id'))
    probe = sqlorm.relationship('probes', back_populates='measurements')
    execution_time = sqla.Column(sqla.DateTime)
    destination_address = sqla.Column(postgresql.INET)
    source_address = sqla.Column(postgresql.INET)
    error_msg = sqla.Column(postgresql.ENUM(MeasurementError))
    rtts = sqla.Column(postgresql.ARRAY(sqla.Float))
    # eventually save ttl if there?

    measurement_result_type = sqla.Column(sqla.String)

    __mapper_args__ = {'polymorphic_on': measurement_result_type}

    @staticmethod
    def parse_from_json(dict):
        NotImplementedError('This method ust be implemented in subclass!\n'
                            'MeasurementResult is an custom abstract base class!')


class LocationResult(object):
    """
    Old Results object with json en/decoding

    Stores the result for a location
    """

    class_name_identifier = 'lr'

    __slots__ = ['location_id', 'rtt', 'location']

    class PropertyKey:
        location_id = '0'
        rtt = '1'

    def __init__(self, location_id: str, rtt: float, location=None):
        """init"""
        self.location_id = location_id
        self.location = location
        self.rtt = rtt

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        return {
            constants.JSON_CLASS_IDENTIFIER: self.class_name_identifier,
            self.PropertyKey.location_id: self.location_id,
            self.PropertyKey.rtt: self.rtt
        }

    @staticmethod
    def create_object_from_dict(dct: dict):
        """Creates a LocationResult object from a dictionary"""
        return LocationResult(dct[LocationResult.PropertyKey.location_id],
                              dct[LocationResult.PropertyKey.rtt])

    def copy(self):
        return LocationResult(self.location_id, self.rtt, location=self.location)
