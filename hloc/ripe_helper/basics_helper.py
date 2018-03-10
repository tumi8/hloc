"""
Functions that will help with the ripe requests
"""

import logging
import time
import multiprocessing as mp
import typing
import datetime
import requests

import ripe.atlas.cousteau as ripe_atlas
import ripe.atlas.cousteau.exceptions as ripe_atlas_exceptions

from hloc.db_utils import probe_for_id, location_for_coordinates

from hloc.models import RipeAtlasProbe

def get_ripe_measurement(measurement_id: int, max_retries: int = -1, logger: logging = None):
    """Call the RIPE measurement entry point to get the ripe measurement with measurement_id"""
    retries = 0
    while True:
        try:
            return ripe_atlas.Measurement(id=measurement_id)
        except ripe_atlas_exceptions.APIResponseError:
            if retries >= max_retries >= 0:
                raise

            retries += 1
            time.sleep(5)
            if logger and retries % 25 == 0:
                logger.exception('Ripe get Measurement (id {}) error!'.format(measurement_id))
            if retries % 5 == 0:
                time.sleep(30)


def get_measurement_ids(ip_addr: str,
                        ripe_slow_down_sema: mp.Semaphore,
                        allowed_measurement_age: int) -> [int]:
    """
    Get ripe measurements for ip_addr
    """

    def next_batch(measurement):
        loc_retries = 0
        while True:
            try:
                measurement.next_batch()
            except ripe_atlas.exceptions.APIResponseError:
                logging.exception('MeasurementRequest APIResponseError next_batch')
                pass
            else:
                break
            time.sleep(5)
            loc_retries += 1

            if loc_retries % 5 == 0:
                logging.error('Ripe next_batch error! {}'.format(ip_addr))

    max_age = int(time.time()) - allowed_measurement_age
    params = {
        'status__in': '2,4,5',
        'target': ip_addr,
        'type': 'ping',
        'stop_time__gte': max_age
        }
    ripe_slow_down_sema.acquire()
    retries = 0

    while True:
        try:
            measurements = ripe_atlas.MeasurementRequest(**params)
        except ripe_atlas.exceptions.APIResponseError:
            logging.exception('MeasurementRequest APIResponseError')
        else:
            break

        time.sleep(5)
        retries += 1

        if retries % 5 == 0:
            logging.error('Ripe MeasurementRequest error! {}'.format(ip_addr))
            time.sleep(30)

    next_batch(measurements)
    if measurements.total_count > 500:
        skip = int(measurements.total_count / 100) - 5

        for _ in range(0, skip):
            next_batch(measurements)

    return [measurement['id'] for measurement in measurements]


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