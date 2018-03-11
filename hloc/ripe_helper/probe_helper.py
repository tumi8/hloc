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
        probe = __parse_probe(probe_dct, db_session)

        if probe:
            return_dct[str(probe.probe_id)] = (probe, 'system-ipv4-rfc1918' in probe_dct['tags'])

        if count % 500 == 0:
            ripe_slow_down_sema.acquire()

    db_session.add_all([probe for probe, _ in return_dct.values()])
    db_session.commit()

    return return_dct


def __parse_probe(probe_dct: typing.Dict[str, typing.Any], db_session) \
        -> typing.Optional[RipeAtlasProbe]:
    if probe_dct['total_uptime'] == 0 or 'geometry' not in probe_dct or \
                    not probe_dct['geometry'] or 'coordinates' not in probe_dct['geometry']:
        return None

    lon = probe_dct['geometry']['coordinates'][1]
    lat = probe_dct['geometry']['coordinates'][0]
    if abs(lat) < 1 and abs(lon) < 1:
        return None

    probe_id = str(probe_dct['id'])
    probe_db_obj = probe_for_id(probe_id, db_session)

    if probe_db_obj and probe_db_obj.is_near(lat, lon):
        return probe_db_obj

    location = location_for_coordinates(lat, lon, db_session)

    probe_db_obj = RipeAtlasProbe(probe_id=probe_id, location=location)

    return probe_db_obj
