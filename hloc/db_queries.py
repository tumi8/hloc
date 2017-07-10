#!/usr/bin/env python3
"""
A collection of queries connected to the location object
"""

import sqlalchemy as sqla

from hloc.models import State, Probe, Session, Domain, MeasurementResult, DomainLabel


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
        db_session.commit()

    return label


def probe_for_id(probe_id: int, db_session: Session) -> Probe:
    """
    searches for a probe with the probe_id
    :param probe_id: the id of the probe
    :param db_session: a data base session on which the queries are executed
    :return (Probe): the Probe with the corresponding id or None
    """
    return db_session.query(Probe).filter(Probe.probe_id == probe_id).first()


def get_measurements_for_domain(domain: Domain,
                                ip_version: str,
                                db_session: Session) -> [MeasurementResult]:
    """
    :param domain: the domain for which measurements should be returned
    :param ip_version: ipv4 or ipv6
    :param db_session: a data base session on which the queries are executed
    :return: all measurements related to this domain
    """
    return db_session.query(MeasurementResult).filter(
        MeasurementResult.destination_address == domain.ip_for_version(ip_version))


def add_labels_to_domain(domain: Domain, db_session: Session):
    for label in domain.name.split('.')[::-1]:
        label_obj = label_for_name(label, db_session)
        domain.labels.append(label_obj)
