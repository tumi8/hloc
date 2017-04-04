#!/usr/bin/env python3
"""The Base of SQLAlchemy imported by all model using it"""

import sqlalchemy.ext.declarative
from hloc.util import engine


Base = sqlalchemy.ext.declarative.declarative_base(bind=engine)

from .location import *
from .probe import *
from .measurement_result import *
from .domain import *

Location.matches = sqlorm.relationship(CodeMatch, back_populates='location_info')


# from hloc.models import MeasurementResult, Probe, RipeAtlasProbe, AvailableType, JSONBase, \
#     LocationCodeType, AirportInfo, LocodeInfo, State, Location, LocationInfo, Domain, DomainLabel, \
#     CodeMatch, DRoPRule


Base.metadata.create_all(engine)
