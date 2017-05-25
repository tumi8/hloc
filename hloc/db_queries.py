#!/usr/bin/env python3
"""
A collection of queries connected to the location object
"""

import sqlalchemy as sqla

from hloc.models import State, Probe, Session


def state_for_code(state_code, state_name, db_session: Session):
    """
    :param state_code: A state code 
    :param state_name: the name of the state
    :param db_session: a data base session on which the queries are executed
    :return: the state object for the state code
    """
    state = db_session.query(State).filter(
        sqla.or_(State.code == state_code, State.name == state_name)).first()

    if state:
        if state_name and not state.name:
            state.name = state_name
        return state

    state = State(name=state_name, code=state_code)
    db_session.add(state)
    return State(name=state_name, code=state_code)


def probe_for_id(probe_id: int, db_session: Session) -> Probe:
    """
    searches
    :param probe_id (int): the id of the probe
    :return (Probe): the Probe with the corresponding id or None
    """
    return db_session.query(Probe).filter(Probe.probe_id == probe_id).first()
