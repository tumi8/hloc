#!/usr/bin/env python3
"""
A collection of queries connected to the location object
"""

import typing
import datetime
import sqlalchemy as sqla
import sqlalchemy.exc
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.sql.expression import func


from hloc.models import State, Probe, Session, Domain, MeasurementResult, DomainLabel, Base, \
    DomainType, Location, LocationInfo, AirportInfo, engine


def create_session_for_process():
    engine.dispose()
    return scoped_session(sessionmaker(autoflush=True, bind=engine))


def recreate_db():
    Base.metadata.drop_all()
    Base.metadata.create_all()


def state_for_code(state_code, state_name, db_session: Session):
    """
    :param state_code: A state code 
    :param state_name: the name of the state
    :param db_session: a data base session on which the queries are executed
    :return: the state object for the state code
    """
    state = db_session.query(State).filter(
        sqla.or_(State.iso3166code == state_code, State.name == state_name)).first()

    if state:
        if state_name and not state.name:
            state.name = state_name
        return state

    state = State(name=state_name, iso3166code=state_code)
    db_session.add(state)
    return state


def label_for_name(label_name: str, db_session: Session):
    """
    Checks for an existing label with the same name and returns it.
    If there is no existing a new one is created
    :param label_name: the label text
    :param db_session: a data base session on which the queries are executed
    :return: the DomainLabel object for the label name
    """
    label = db_session.query(DomainLabel).filter(DomainLabel.name == label_name).first()

    if not label:
        label = DomainLabel(label_name)
        db_session.add(label)
        try:
            db_session.commit()
        except sqlalchemy.exc.IntegrityError:
            db_session.rollback()
            label = db_session.query(DomainLabel).filter(DomainLabel.name == label_name).first()
            if not label:
                raise
    return label


def location_for_coordinates(lat: float, lon: float, db_session: Session, create_new: bool=True) \
        -> Location:
    location = db_session.query(Location).filter_by(lat=lat, lon=lon).first()

    if location or not create_new:
        return location

    location = Location(lat, lon)
    db_session.add(location)
    return location


def location_for_iata_code(iata_code: str, db_session: Session) -> LocationInfo:
    location = db_session.query(LocationInfo).join(AirportInfo)\
        .filter(
            iata_code == sqla.any_(AirportInfo.iata_codes)
        ).first()
    return location


def probe_for_id(probe_id: str, db_session: Session) -> Probe:
    """
    searches for a probe with the probe_id
    :param probe_id: the id of the probe
    :param db_session: a data base session on which the queries are executed
    :return (Probe): the Probe with the corresponding id or None
    """
    return db_session.query(Probe).filter_by(probe_id=probe_id).first()


def domain_by_id(domain_id: int, db_session: Session) -> Domain:
    """
    return the domain with the id
    :param domain_id: the id of the domain
    :param db_session:  a data base session on which the queries are executed
    :return (Domain): the Domain for the searched id
    """
    return db_session.query(Domain).filter(Domain.id == domain_id).first()


def domains_for_ids(domain_ids: [int], db_session: Session) -> [Domain]:
    """
    return all domains with an id in domain_ids
    :param domain_ids: the ids of the domains
    :param db_session:  a data base session on which the queries are executed
    :return ([Domain]): the matching domains for the domain_ids
    """
    return db_session.query(Domain).filter(Domain.id.in_(domain_ids))


def get_measurements_for_domain(domain: Domain,
                                ip_version: str,
                                max_measurement_age: typing.Optional[int],
                                sorted_return: bool,
                                db_session: Session,
                                allow_all_zmap_measurements: bool = False) -> [MeasurementResult]:
    """
    :param domain: the domain for which measurements should be returned
    :param ip_version: ipv4 or ipv6
    :param max_measurement_age: the maximal age of the measurements in seconds
    :param sorted_return: if the returned values should be ordered by the rtt set to True
    :param db_session: a data base session on which the queries are executed
    :param allow_all_zmap_measurements: Allow zmap measurement regardless of their timestamp
    :return: all measurements related to this domain
    """

    if max_measurement_age:
        if allow_all_zmap_measurements:
            query = db_session.query(MeasurementResult).filter(
                sqla.and_(
                    MeasurementResult.destination_address == domain.ip_for_version(ip_version),
                    sqla.or_(
                        MeasurementResult.timestamp >= datetime.datetime.now() -
                        datetime.timedelta(seconds=max_measurement_age),
                        MeasurementResult.measurement_result_type == 'zmap_measurement'
                             )
                )
            )
        else:
            query = db_session.query(MeasurementResult).filter(
                sqla.and_(
                    MeasurementResult.destination_address == domain.ip_for_version(ip_version),
                    MeasurementResult.timestamp >= datetime.datetime.now() - datetime.timedelta(
                        seconds=max_measurement_age),
                )
            )
    else:
        query = db_session.query(MeasurementResult).filter(
            MeasurementResult.destination_address == domain.ip_for_version(ip_version)
        )

    if sorted_return:
        query = query.order_by(MeasurementResult.timestamp.desc())

    return query


def get_all_domain_ids_splitted(index: int, block_limit: int, nr_processes: int,
                                domain_types: typing.List[DomainType], db_session: Session) \
        -> typing.Generator[int, None, None]:
    for domain_id in db_session.query(Domain.id).filter(
            sqla.and_(
                Domain.id % nr_processes == index,
                Domain.classification_type.in_(domain_types)
            )).yield_per(block_limit):
        yield domain_id


def get_all_domains_splitted_efficient(index: int, block_limit: int, nr_processes: int,
                                       domain_types: typing.List[DomainType], db_session: Session) \
        -> typing.Generator[Domain, None, None]:
    for domain in db_session.query(Domain).filter(
            sqla.and_(
                Domain.id % nr_processes == index,
                Domain.classification_type.in_(domain_types),
                func.random() * 3 < 1
            )).yield_per(block_limit):
        yield domain
