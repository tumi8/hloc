"""
Functions that will help with the ripe API probe requests
"""

import typing

import ripe.atlas.cousteau as ripe_atlas

from hloc.models import RipeAtlasProbe
from hloc.db_utils import probe_for_id, location_for_coordinates


def get_probes(db_session, ripe_slow_down_sema) -> typing.Dict[str, RipeAtlasProbe]:
    probe_request = ripe_atlas.ProbeRequest()
    return_dct = {}

    # chunk size is 500
    count = 0
    for probe_dct in probe_request:
        count += 1
        if probe_dct['total_uptime'] > 0 and probe_dct['latitude'] and probe_dct['longitude']:
            probe = __parse_probe(probe_dct, db_session)
            return_dct[str(probe.probe_id)] = (probe, 'system-ipv4-rfc1918' in probe_dct['tags'])
        ripe_slow_down_sema.acquire()

    db_session.add_all([probe for probe, _ in return_dct.values()])
    db_session.commit()

    return return_dct


def __parse_probe(probe_dct: typing.Dict[str, typing.Any], db_session) -> RipeAtlasProbe:
    probe_id = str(probe_dct['id'])
    probe_db_obj = probe_for_id(probe_id, db_session)

    if probe_db_obj and probe_db_obj.is_near(probe_dct['latitude'], probe_dct['longitude']):
        return probe_db_obj

    location = location_for_coordinates(probe_dct['latitude'],
                                        probe_dct['longitude'],
                                        db_session)

    probe_db_obj = RipeAtlasProbe(probe_id=probe_id, location=location)

    return probe_db_obj
