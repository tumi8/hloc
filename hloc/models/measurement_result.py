#!/usr/bin/env python3
"""
 * All measurement result classes used by the HLOC framework
"""

import enum
import datetime
import typing
import sqlalchemy as sqla
import sqlalchemy.orm as sqlorm
from sqlalchemy.dialects import postgresql


from hloc.models.sql_alchemy_base import Base
from .enums import MeasurementError, MeasurementProtocol


class MeasurementResult(Base):
    """the abstract base class for a measurement result"""

    __tablename__ = 'measurement_results'

    id = sqla.Column(sqla.Integer, primary_key=True)
    probe_id = sqla.Column(sqla.Integer, sqla.ForeignKey('probes.id'), nullable=False)
    timestamp = sqla.Column(sqla.DateTime, nullable=False)
    destination_address = sqla.Column(postgresql.INET, nullable=False, index=True)
    source_address = sqla.Column(postgresql.INET)
    error_msg = sqla.Column(postgresql.ENUM(MeasurementError))
    rtt = sqla.Column(sqla.Float, nullable=False)
    ttl = sqla.Column(sqla.Integer)
    protocol = sqla.Column(postgresql.ENUM(MeasurementProtocol))
    behind_nat = sqla.Column(sqla.Boolean, default=False)
    from_traceroute = sqla.Column(sqla.Boolean, default=False)

    probe = sqlorm.relationship('Probe', back_populates='measurements', cascade='all')

    measurement_result_type = sqla.Column(sqla.String)

    __mapper_args__ = {'polymorphic_on': measurement_result_type,
                       'polymorphic_identity': 'measurement'}

    def __init__(self, **kwargs):
        self.rtts = []

        for name, value in kwargs.items():
            setattr(self, name, value)

        super().__init__()

    @property
    def min_rtt(self):
        return self.rtt


class RipeMeasurementResult(MeasurementResult):
    __mapper_args__ = {
        'polymorphic_identity': 'ripe_measurement'
    }

    class RipeMeasurementResultKey(enum.Enum):
        destination_addr = 'dst_addr'
        source_addr = 'src_addr'
        rtt_dicts = 'result'
        rtt = 'rtt'
        timestamp = 'timestamp'
        measurement_id = 'msm_id'

    ripe_measurement_id = sqla.Column(sqla.Integer)

    @staticmethod
    def create_from_dict(ripe_result_dict) -> 'RipeMeasurementResult':
        """
        
        :param ripe_result_dict: the measurement dict from ripe.atlas.cousteau.AtlasResultsRequest  
                                 return value
        :return (RipeMeasurementResult): Our MeasurementResult object
        """
        measurement_result = RipeMeasurementResult()
        measurement_result.destination_address = \
            ripe_result_dict[RipeMeasurementResult.RipeMeasurementResultKey.destination_addr.value]
        measurement_result.source_address = \
            ripe_result_dict[RipeMeasurementResult.RipeMeasurementResultKey.source_addr.value]
        measurement_result.ripe_measurement_id = \
            ripe_result_dict[RipeMeasurementResult.RipeMeasurementResultKey.measurement_id.value]
        rtts = []
        for ping in measurement_result[
                           RipeMeasurementResult.RipeMeasurementResultKey.rtt_dicts.value]:
            rtt_value = ping.get(RipeMeasurementResult.RipeMeasurementResultKey.rtt.value, None)
            if rtt_value:
                try:
                    rtts.append(float(rtt_value))
                except ValueError:
                    continue

        measurement_result.rtts = rtts
        if not rtts:
            measurement_result.error_msg = MeasurementError.not_reachable

        measurement_result.timestamp = datetime.datetime.fromtimestamp(
            ripe_result_dict[RipeMeasurementResult.RipeMeasurementResultKey.timestamp.value])

        return measurement_result


class CaidaArkMeasurementResult(MeasurementResult):
    __mapper_args__ = {
        'polymorphic_identity': 'caida_ark_measurement'
    }

    @staticmethod
    def create_from_archive_line(archive_line: str, caida_probe_id: str) \
            -> 'CaidaArkMeasurementResult':
        timestamp_str, src, dst, rtt_str = archive_line.split(';')
        timestamp = datetime.datetime.fromtimestamp(int(timestamp_str))
        rtt = float(rtt_str)

        measurement_result = CaidaArkMeasurementResult(probe_id=caida_probe_id,
                                                       timestamp=timestamp,
                                                       source_address=src,
                                                       destination_address=dst,
                                                       rtts=[rtt],
                                                       measurement_protocol=MeasurementProtocol.icmp
                                                       )

        return measurement_result


__all__ = [
    'MeasurementResult',
    'RipeMeasurementResult',
    'CaidaArkMeasurementResult',
   ]
