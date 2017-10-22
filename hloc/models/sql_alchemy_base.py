#!/usr/bin/env python3
"""The Base of SQLAlchemy imported by all model using it"""

import sqlalchemy.ext.declarative
from sqlalchemy import create_engine

Base = sqlalchemy.ext.declarative.declarative_base()
