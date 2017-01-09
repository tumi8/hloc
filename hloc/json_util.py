"""
This module collects all functions related to file saving in json
"""

import json

from . import constants
from .models import *


def json_object_encoding(obj):
    """Overrides the default method from the JSONEncoder"""
    if isinstance(obj, JSONBase):
        return obj.dict_representation()

    raise TypeError('Object not handled by the JSON encoding function ({})'.format(type(obj)))


def json_object_decoding(dct):
    """Decodes the dictionary to an object if it is one"""
    if constants.JSON_CLASS_IDENTIFIER in dct:
        # if dct[constants.JSON_CLASS_IDENTIFIER] == LocationInfo.class_name_identifier:
        #     return LocationInfo.create_object_from_dict(dct)
        # if dct[constants.JSON_CLASS_IDENTIFIER] == AirportInfo.class_name_identifier:
        #     return AirportInfo.create_object_from_dict(dct)
        # if dct[constants.JSON_CLASS_IDENTIFIER] == LocodeInfo.class_name_identifier:
        #     return LocodeInfo.create_object_from_dict(dct)
        # if dct[constants.JSON_CLASS_IDENTIFIER] == LocationResult.class_name_identifier:
        #     return LocationResult.create_object_from_dict(dct)
        # if dct[constants.JSON_CLASS_IDENTIFIER] == Domain.class_name_identifier:
        #     return Domain.create_object_from_dict(dct)
        # if dct[constants.JSON_CLASS_IDENTIFIER] == DomainLabel.class_name_identifier:
        #     return DomainLabel.create_object_from_dict(dct)
        # if dct[constants.JSON_CLASS_IDENTIFIER] == CodeMatch.class_name_identifier:
        #     return CodeMatch.create_object_from_dict(dct)
        # if dct[constants.JSON_CLASS_IDENTIFIER] == Location.class_name_identifier:
        #     return Location.create_object_from_dict(dct)
        if dct[constants.JSON_CLASS_IDENTIFIER] == DRoPRule.class_name_identifier:
            return DRoPRule.create_object_from_dict(dct)
    return dct


def json_dump(encoding_var, file_ptr):
    """
    Dumps the encoding_var to the file in file_ptr with the
    json_object_encoding function
    :param encoding_var: the variable you want to encode in json
    :param file_ptr: the file where the
    :return: None
    """
    # msgpack.pack(encoding_var, file_ptr, default=json_object_encoding)
    json.dump(encoding_var, file_ptr, default=json_object_encoding)


def json_load(file_ptr):
    """
    Loads the content of the file and returns the decoded result
    :param file_ptr: the pointer to the file where json should load and decode
    :return: the variable from json.load
    """
    # sreturn msgpack.unpack(file_ptr, object_hook=json_object_decoding)
    return json.load(file_ptr, object_hook=json_object_decoding)


def json_loads(json_str):
    """
    Decodes the content of the string variable and returns it
    :param json_str: the string which content should be decoded
    :return: the variable from json.loads
    """
    # return msgpack.unpackb(json_str, object_hook=json_object_decoding)
    return json.loads(json_str, object_hook=json_object_decoding)
