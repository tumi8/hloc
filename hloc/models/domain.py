"""
All Domain related objects
"""

from hloc import constants
from .json_base import JSONBase
from .location import *


class Domain(object):
    """
    Holds the information for one domain
    DO NOT SET the DOMAIN NAME after calling the constructor!
    """

    # TODO use ipaddress stdlib module

    class_name_identifier = 'd'

    __slots__ = ['domain_name', 'ip_address', 'ipv6_address', 'domain_labels', 'location_id',
                 'location']

    class PropertyKey:
        domain_name = '0'
        ip_address = '1'
        ipv6_address = '2'
        domain_labels = '3'
        location_id = '4'

    def __init__(self, domain_name, ip_address=None, ipv6_address=None):
        """init"""

        def create_labels() -> [DomainLabel]:
            labels = []
            for label in domain_name.split('.')[::-1]:
                labels.append(DomainLabel(label))
            return labels

        self.domain_name = domain_name
        self.ip_address = ip_address
        self.ipv6_address = ipv6_address
        self.domain_labels = create_labels()
        self.location_id = None
        self.location = None

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
    def all_matches(self):
        """Returns all matches of the domain"""
        matches = []
        location_ids = set()
        for label in self.domain_labels[::-1]:
            for match in label.matches:
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

    def ip_for_version(self, version: str) -> str:
        """returns the version corresponding ip address"""
        if version == constants.IPV4_IDENTIFIER:
            return self.ip_address
        elif version == constants.IPV6_IDENTIFIER:
            return self.ipv6_address
        else:
            raise ValueError('{} is not a valid IP version'.format(version))

    def dict_representation(self) -> [str, object]:
        """Returns a dictionary with the information of the object"""
        ret_dict = {
            constants.JSON_CLASS_IDENTIFIER: self.class_name_identifier,
            self.PropertyKey.domain_name: self.domain_name,
            self.PropertyKey.ip_address: self.ip_address,
            self.PropertyKey.ipv6_address: self.ipv6_address,
            self.PropertyKey.domain_labels: [label.dict_representation() for label in
                                             self.domain_labels],
        }
        if self.location_id is not None:
            ret_dict[self.PropertyKey.location_id] = self.location_id
        elif self.location:
            if isinstance(self.location, Location):
                ret_dict[self.PropertyKey.location_id] = self.location.id
            else:
                ret_dict[self.PropertyKey.location_id] = self.location.dict_representation()
        return ret_dict

    @staticmethod
    def create_object_from_dict(dct, locations: [str, object] = None):
        """Creates a Domain object from a dictionary"""
        obj = Domain(dct[Domain.PropertyKey.domain_name], dct[Domain.PropertyKey.ip_address],
                     dct[Domain.PropertyKey.ipv6_address])
        if Domain.PropertyKey.domain_labels in dct:
            del obj.domain_labels[:]
            obj.domain_labels = dct[Domain.PropertyKey.domain_labels][:]
        if Domain.PropertyKey.location_id in dct:
            if isinstance(dct[Domain.PropertyKey.location_id], (int, str)):
                obj.location_id = dct[Domain.PropertyKey.location_id]
                if locations and obj.location_id in locations:
                    obj.location = locations[obj.location_id]
            elif isinstance(dct[Domain.PropertyKey.location_id], GPSLocation):
                obj.location = dct[Domain.PropertyKey.location_id]

        return obj

    def copy(self):
        obj = Domain(self.domain_name, self.ip_address, self.ipv6_address)
        obj.domain_labels = [domain_label.copy() for domain_label in self.domain_labels]
        obj.location_id = self.location_id
        obj.location = self.location
        return obj


class DomainLabel(JSONBase):
    """The model for a domain name label"""

    class_name_identifier = 'dl'

    __slots__ = ['label', 'matches']

    class PropertyKey:
        label = '0'
        matches = '1'

    def __init__(self, label):
        """
        init
        :param label: the domain label
        """
        self.label = label
        self.matches = []

    @property
    def sub_labels(self):
        """Returns a list of strings with the label separated by dash"""
        return self.label.split('-')

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        return {
            constants.JSON_CLASS_IDENTIFIER: self.class_name_identifier,
            self.PropertyKey.label: self.label,
            self.PropertyKey.matches: [match.dict_representation() for match in self.matches]
        }

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a DomainLabel object from a dictionary"""
        obj = DomainLabel(dct[DomainLabel.PropertyKey.label])
        obj.matches = dct[DomainLabel.PropertyKey.matches][:]

        return obj

    def copy(self):
        obj = DomainLabel(self.label)
        obj.matches = [match.copy() for match in self.matches]
        return obj


class DomainLabelMatch(JSONBase):
    """The model for a Match between a domain name label and a location code"""

    class_name_identifier = 'dlm'

    __slots__ = ['location_id', 'code_type', 'code', 'matching',
                 'matching_distance', 'matching_rtt', 'possible']

    class PropertyKey:
        location_id = '0'
        code_type = '1'
        code = '2'
        matching = '3'
        matching_distance = '4'
        matching_rtt = '5'
        possible = '6'

    def __init__(self, location_id: int, code_type: LocationCodeType, code=None, possible=True):
        """init"""
        self.location_id = location_id
        self.code_type = code_type
        self.code = code
        self.matching = False
        self.matching_distance = None
        self.matching_rtt = None
        self.possible = possible

    def dict_representation(self):
        """Returns a dictionary with the information of the object"""
        dct = {
            constants.JSON_CLASS_IDENTIFIER: self.class_name_identifier,
            self.PropertyKey.location_id: self.location_id,
            self.PropertyKey.code_type: self.code_type.value,
            self.PropertyKey.code: self.code,
            self.PropertyKey.possible: self.possible,
        }
        if self.matching:
            dct[self.PropertyKey.matching] = self.matching
        if self.matching_distance:
            dct[self.PropertyKey.matching_distance] = self.matching_distance
        if self.matching_rtt:
            dct[self.PropertyKey.matching_rtt] = self.matching_rtt
        return dct

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a DomainLabel object from a dictionary"""
        obj = DomainLabelMatch(dct[DomainLabelMatch.PropertyKey.location_id],
                               LocationCodeType(dct[DomainLabelMatch.PropertyKey.code_type]))
        if DomainLabelMatch.PropertyKey.matching in dct:
            obj.matching = dct[DomainLabelMatch.PropertyKey.matching]
        if DomainLabelMatch.PropertyKey.matching_distance in dct:
            obj.matching_distance = dct[DomainLabelMatch.PropertyKey.matching_distance]
        if DomainLabelMatch.PropertyKey.matching_rtt in dct:
            obj.matching_rtt = dct[DomainLabelMatch.PropertyKey.matching_rtt]
        if DomainLabelMatch.PropertyKey.code in dct:
            obj.code = dct[DomainLabelMatch.PropertyKey.code]
        if DomainLabelMatch.PropertyKey.possible in dct:
            obj.possible = dct[DomainLabelMatch.PropertyKey.possible]
        return obj

    def copy(self):
        obj = DomainLabelMatch(self.location_id, self.code_type, self.code, self.possible)
        obj.matching = self.matching
        obj.matching_rtt = self.matching_rtt
        obj.matching_distance = self.matching_distance
        return obj


__all__ = ['Domain',
           'DomainLabel',
           'DomainLabelMatch',
           ]
