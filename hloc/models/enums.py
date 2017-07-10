#!/usr/bin/env python3
"""
In this module all enums are collected
"""

import enum
import logging


@enum.unique
class LocationCodeType(enum.Enum):
    iata = 0
    icao = 1
    faa = 2
    clli = 3
    locode = 4
    geonames = 5

    @property
    def regex(self):
        """
        :returns the pattern for regex matching a code of the type
        :return: str
        """
        base = r'[a-zA-Z]'
        if self == LocationCodeType.iata:
            pattern = base + r'{3}'
        elif self == LocationCodeType.icao:
            pattern = base + r'{4}'
        elif self == LocationCodeType.clli:
            pattern = base + r'{6}'
        elif self == LocationCodeType.locode:
            pattern = base + r'{5}'
        elif self == LocationCodeType.geonames:
            pattern = r'[a-zA-Z]+'
        else:
            logging.error('WTF? should not be possible')
            return

        return r'(?P<type>' + pattern + r')'


@enum.unique
class MeasurementError(enum.Enum):
    not_reachable = 'not_reachable'
    probe_not_available = 'probe_not_available'
    probe_error = 'probe_error'


@enum.unique
class AvailableType(enum.Enum):
    ipv4_available = '0'
    ipv6_available = '1'
    both_available = '2'
    not_available = '3'
    unknown = '4'


@enum.unique
class DomainType(enum.Enum):
    blacklisted = 'blacklisted'
    ip_encoded = 'ip_encode'
    bad_tld = 'bad_tld'
    invalid_characters = 'invalid_characters'
    valid = 'valid'


@enum.unique
class DomainLocationType(enum.Enum):
    verified = 'verified'
    verification_not_possible = 'verification not possible'
    no_match_possible = 'no match possible'
    not_reachable = 'not reachable'


__all__ = ['LocationCodeType',
           'MeasurementError',
           'AvailableType',
           'DomainLocationType',
           'DomainType'
           ]
