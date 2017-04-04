#!/usr/bin/env python3
"""The Base of SQLAlchemy imported by all model using it"""

import sqlalchemy.ext.declarative
from hloc.util import engine


Base = sqlalchemy.ext.declarative.declarative_base(bind=engine)


from hloc.models import MeasurementResult, Probe, RipeAtlasProbe, AvailableType, JSONBase, \
    LocationCodeType, AirportInfo, LocodeInfo, State, Location, LocationInfo, Domain, DomainLabel, \
    CodeMatch, DRoPRule


Base.metadata.create_all(engine)
