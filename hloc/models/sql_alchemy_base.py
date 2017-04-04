#!/usr/bin/env python3
"""The Base of SQLAlchemy imported by all model using it"""

import sqlalchemy.ext.declarative
import sqlalchemy.orm as sqlorm
from hloc.util import engine


Base = sqlalchemy.ext.declarative.declarative_base(bind=engine)

from .location import *
from .probe import *
from .measurement_result import *
from .domain import *

Location.matches = sqlorm.relationship(CodeMatch, back_populates='location_info')


Base.metadata.create_all(engine)
