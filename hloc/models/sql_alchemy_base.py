#!/usr/bin/env python3
"""The Base of SQLAlchemy imported by all model using it"""

import sqlalchemy.ext.declarative
from hloc.util import engine

from hloc import models


Base = sqlalchemy.ext.declarative.declarative_base(bind=engine)
Base.metadata.create_all(engine)
