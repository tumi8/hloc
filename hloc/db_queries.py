#!/usr/bin/env python3
"""
A collection of queries connected to the location object
"""

import sqlalchemy as sqla

from hloc.models import State, Probe, Session, Domain, MeasurementResult


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
    return State(name=state_name, iso3166code=state_code)


def probe_for_id(probe_id: int, db_session: Session) -> Probe:
    """
    searches for a probe with the probe_id
    :param probe_id (int): the id of the probe
    :return (Probe): the Probe with the corresponding id or None
    """
    return db_session.query(Probe).filter(Probe.probe_id == probe_id).first()


def get_measurements_for_domain(domain: Domain, ip_version: str, db_session: Session) -> [MeasurementResult]:
    """
    
    :param domain: the domain for which measurements should be returned
    :return: all measurements related to this domain
    """
    return db_session.query(MeasurementResult).filter(MeasurementResult.destination_address == domain.ip_for_version(ip_version))