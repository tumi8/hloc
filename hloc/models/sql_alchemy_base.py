#!/usr/bin/env python3
"""The Base of SQLAlchemy imported by all model using it"""

import sqlalchemy.ext.declarative


Base = sqlalchemy.ext.declarative.declarative_base()
