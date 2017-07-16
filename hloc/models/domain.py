#!/usr/bin/env python3
"""
All Domain related objects
"""

import sqlalchemy as sqla
import sqlalchemy.orm as sqlorm
from sqlalchemy.dialects import postgresql

from hloc import constants
from .sql_alchemy_base import Base
from .enums import LocationCodeType, DomainType
from .location import LocationHint, domain_location_hints_table, location_hint_label_table


class CodeMatch(LocationHint):
    """The model for a Match between a domain name label and a location code"""

    __mapper_args__ = {'polymorphic_identity': 'code_match'}

    code_type = sqla.Column(postgresql.ENUM(LocationCodeType), nullable=False)
    code = sqla.Column(sqla.String(50), nullable=False)

    location_info = sqlorm.relationship('LocationInfo', back_populates='matches')

    def __init__(self, location_id, domain_label,
                 code_type: LocationCodeType, code=None):
        """init"""
        self.location_id = location_id
        self.code_type = code_type
        self.code = code
        self.labels.append(domain_label)


domain_to_label_table = sqla.Table('domain_to_labels', Base.metadata,
                                    sqla.Column('domain_id', sqla.Integer,
                                                sqla.ForeignKey('domains.id', ondelete='cascade')),
                                    sqla.Column('domain_label_id', sqla.Integer,
                                                sqla.ForeignKey('domain_labels.id', ondelete='cascade')))


class DomainLabel(Base):
    """The model for a domain name label"""

    __tablename__ = 'domain_labels'

    id = sqla.Column(sqla.Integer, primary_key=True)
    name = sqla.Column(sqla.String(100), unique=True, index=True, nullable=False)
    last_searched = sqla.Column(sqla.DateTime)


    domains = sqlorm.relationship("Domain",
                                  secondary=domain_to_label_table,
                                  back_populates="labels")
    hints = sqlorm.relationship(LocationHint,
                                       secondary=location_hint_label_table,
                                       back_populates="labels")

    def __init__(self, name: str):
        """
        init
        :param name: the domain label string
        """
        self.name = name
        self.matches = []

    @property
    def sub_labels(self):
        """Returns a list of strings with the label separated by dash"""
        return self.name.split('-')


class Domain(Base):
    """
    Holds the information for one domain
    DO NOT SET the DOMAIN NAME after calling the constructor!
    """

    __tablename__ = 'domains'

    id = sqla.Column(sqla.Integer, primary_key=True)
    name = sqla.Column(sqla.String(200), nullable=False)
    ipv4_address = sqla.Column(postgresql.INET)
    ipv6_address = sqla.Column(postgresql.INET)
    classification_type = sqla.Column(postgresql.ENUM(DomainType), default=DomainType.valid)

    labels = sqlorm.relationship(DomainLabel,
                                 secondary=domain_to_label_table,
                                 back_populates='domains')
    hints = sqlorm.relationship(LocationHint,
                                secondary=domain_location_hints_table,
                                back_populates='domains')

    # TODO create function to check for a validated location

    def __init__(self, domain_name, ipv4_address=None, ipv6_address=None):
        """init"""

        self.name = domain_name
        self.ipv4_address = ipv4_address
        self.ipv6_address = ipv6_address
        self.labels = []

    @property
    def drop_domain_keys(self):
        """returns only the second level domain and the top level domain"""
        domain_parts = self.domain_name.split('.')
        if len(domain_parts) <= 1:
            return domain_parts
        main_domain = '.'.join(domain_parts[-2:])
        domain_parts.pop()
        domain_parts[-1] = main_domain
        return domain_parts[::-1]

    @property
    def all_label_matches(self):
        """Returns all matches of the domain"""
        matches = []
        location_ids = set()
        for label in self.domain_labels[::-1]:
            for match in label.code_matches:
                if match.location_id not in location_ids:
                    location_ids.add(match.location_id)
                    matches.append(match)
        return matches

    @property
    def possible_matches(self):
        """Returns all matches which are possible (according to measurements)"""
        return [match for match in self.all_matches if match.possible]

    @property
    def matches_count(self) -> int:
        """Counts the amount of matches for this domain"""
        return len(self.all_matches)

    @property
    def matching_match(self):
        """Returns the match where we found the correct location"""
        for match in self.all_matches:
            if match.matching:
                return match
        else:
            return None

    def ip_for_version(self, version: str) -> postgresql.INET:
        """returns the version corresponding ip address"""
        if version == constants.IPV4_IDENTIFIER:
            return self.ipv4_address
        elif version == constants.IPV6_IDENTIFIER:
            return self.ipv6_address
        else:
            raise ValueError('{} is not a valid IP version'.format(version))


__all__ = ['Domain',
           'DomainLabel',
           'CodeMatch',
           ]
