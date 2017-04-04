#!/usr/bin/env python3
"""The Base of SQLAlchemy imported by all model using it"""

import sqlalchemy.ext.declarative
from sqlalchemy import create_engine

# echo writes sql to output
engine = create_engine('postgresql://hloc:hloc2017@localhost/hloc-debugdb', echo=False)
Base = sqlalchemy.ext.declarative.declarative_base(bind=engine)
