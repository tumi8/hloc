
import abc
from .location import GPSLocation, Location, AirportInfo, LocodeInfo
from .domain import Domain, DomainLabel, DomainLabelMatch
from .measurement_result import LocationResult
from .drop_rule import DRoPRule


class JSONBase(metaclass=abc.ABCMeta):
    """
    The Base class to JSON encode your object with json_encoding_func
    """
    @property
    @abc.abstractmethod
    def class_name_identifier(self) -> str:
        """The class identifier for json"""
        pass

    @abc.abstractmethod
    def dict_representation(self):
        pass

    @staticmethod
    @abc.abstractmethod
    def create_object_from_dict(dct):
        pass

    @abc.abstractmethod
    def copy(self):
        pass


JSONBase.register(GPSLocation)
JSONBase.register(Location)
JSONBase.register(AirportInfo)
JSONBase.register(LocodeInfo)
JSONBase.register(Domain)
JSONBase.register(DomainLabel)
JSONBase.register(DomainLabelMatch)
JSONBase.register(LocationResult)
JSONBase.register(DRoPRule)

__all__ = ['JSONBase']
