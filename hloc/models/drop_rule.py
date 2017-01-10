#!/usr/bin/env python3
"""
Module for the drop rules
"""

import collections
import logging
import re

from hloc import constants
from .location import LocationCodeType


class DRoPRule(object):
    """Stores a DRoP rule to find locations in domain names"""

    class_name_identifier = 'dr'

    __slots__ = ['name', 'source', '_rules', '_regex_rules']

    class PropertyKey:
        name = '0'
        source = '1'
        rules = '2'

    def __init__(self, name: str, source: str):
        """init"""
        self.name = name
        self.source = source
        self._rules = []
        self._regex_rules = None

    def dict_representation(self) -> dict:
        """Returns a dictionary with the information of the object"""
        return {
            constants.JSON_CLASS_IDENTIFIER: self.class_name_identifier,
            self.PropertyKey.name: self.name,
            self.PropertyKey.source: self.source,
            self.PropertyKey.rules: [rule.as_norm_dict() for rule in self._rules]
        }

    @property
    def rules(self) -> [str]:
        """
        :returns all rules saved in this object in a named tuple (rule: str, type: LocationCodeType)
        :return: list(collections.namedtuple('Rule', ['rule', 'type']))
        """
        return self._rules

    @property
    def regex_pattern_rules(self) -> [(re, LocationCodeType)]:
        """
        :returns all rules saved in this object as patterns for regex execution
        :return: list(String)
        """
        if self._regex_rules is None:
            ret_rules = []
            for rule in self._rules:
                ret_rules.append((re.compile(rule.rule.replace('{}', rule.type.regex)), rule.type))
            self._regex_rules = ret_rules

        return self._regex_rules

    def add_rule(self, rule: str, code_type: LocationCodeType):
        """adds a rule with the LocationCodeType set in type"""
        self._rules.append(DRoPRule.NamedTupleRule(rule, code_type))

    @staticmethod
    def create_object_from_dict(dct):
        """Creates a DroPRuler object from a dictionary"""
        obj = DRoPRule(dct[DRoPRule.PropertyKey.name], dct[DRoPRule.PropertyKey.source])
        for rule in dct[DRoPRule.PropertyKey.rules]:
            obj.add_rule(rule[DRoPRule.NamedTupleRule.PropertyKey.rule],
                         LocationCodeType(rule[DRoPRule.NamedTupleRule.PropertyKey.rule_type]))
        return obj

    def copy(self):
        obj = DRoPRule(self.name, self.source)
        obj._rules = [rule.copy() for rule in self._rules]
        return obj

    @staticmethod
    def create_rule_from_yaml_dict(dct):
        """Creates a DroPRule object from a DRoP-Yaml dictionary"""
        obj = DRoPRule(dct['name'][5:], dct['source'])
        for rule in dct['rules']:
            if rule['mapping_required'] != 1:
                logging.warning('mapping required != 1 for ' + rule)
            else:
                rule_type_match = constants.DROP_RULE_TYPE_REGEX.search(rule['regexp'])
                if rule_type_match:
                    drop_rule_type = rule_type_match.group('type')
                    if drop_rule_type == 'pop':
                        our_rule_type = LocationCodeType.geonames
                    elif drop_rule_type in ['iata', 'icao', 'locode', 'clli']:
                        our_rule_type = getattr(LocationCodeType, drop_rule_type)
                    else:
                        logging.warning('drop rule type not in list: ' + drop_rule_type)
                        continue
                    rule_str = rule['regexp'].replace(rule_type_match.group(0), '{}')
                    obj.add_rule(rule_str, our_rule_type)

        return obj

    class NamedTupleRule(collections.namedtuple('Rule', ['rule', 'type'])):
        __slots__ = ()

        class PropertyKey:
            rule = '0'
            rule_type = '1'

        def as_norm_dict(self) -> dict:
            return {self.PropertyKey.rule: self.rule, self.PropertyKey.rule_type: self.type.value}

        def __str__(self):
            return 'Rule(regexrule: {}, type: {})'.format(self.rule, self.type.name)

        def copy(self):
            return DRoPRule.NamedTupleRule(self.rule, self.type)


__all__ = ['DRoPRule']
