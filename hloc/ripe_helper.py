"""
Functions that will help with the ripe requests
"""

import logging
import time
import multiprocessing as mp
import random
import typing

import ripe.atlas.cousteau as ripe_atlas
import ripe.atlas.cousteau.exceptions as ripe_atlas_exceptions

from .models import RipeAtlasProbe, RipeMeasurementResult, MeasurementResult, LocationInfo


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


def __get_measurements_for_nodes(measurement_ids: [int],
                                 ripe_slow_down_sema: mp.Semaphore,
                                 near_nodes: [RipeAtlasProbe],
                                 allowed_measurement_age: int) \
        -> typing.Generator[(int, [RipeMeasurementResult])]:
    """Loads all results for all measurements if they are less than a year ago"""

    node_dct = {}
    for node in near_nodes:
        node_dct[node.probe_id] = node

    for measurement_id in measurement_ids:
        allowed_start_time = int(time.time()) - allowed_measurement_age

        params = {
            'msm_id': measurement_id,
            'start': allowed_start_time,
            'probe_ids': [node.probe_id for node in near_nodes][:1000]
            }

        ripe_slow_down_sema.acquire()
        success, result_list = ripe_atlas.AtlasResultsRequest(**params).create()
        retries = 0
        while not success and retries < 5:
            logging.debug('AtlasResultsRequest error! {}'.format(result_list))
            time.sleep(10 + (random.randrange(0, 500) / 100))
            ripe_slow_down_sema.acquire()
            success, result_list = ripe_atlas.AtlasResultsRequest(**params).create()
            if not success:
                retries += 1

        if retries > 4:
            logging.error('AtlasResultsRequest error! {}'.format(result_list))
            continue

        measurements = []
        for res in result_list:
            ripe_measurement = RipeMeasurementResult.create_from_dict(res)
            ripe_measurement.probe = node_dct[res['prb_id']]

            if ripe_measurement.min_rtt:
                measurements.append(ripe_measurement)

        yield measurement_id, result_list


def check_measurements_for_nodes(measurement_ids: [int], location: LocationInfo,
                                 nodes: [RipeAtlasProbe], results: [MeasurementResult],
                                 ripe_slow_down_sema: mp.Semaphore, allowed_measurement_age: int) \
        -> typing.Optional[MeasurementResult]:
    """
    Check the measurements list for measurements from near_nodes
    :rtype: (float, dict)
    """
    if not measurement_ids:
        return None

    measurement_results = __get_measurements_for_nodes(measurement_ids,
                                                     ripe_slow_down_sema,
                                                     nodes)
    logging.debug('got measurement results')
    temp_result_rtt = None
    date_n = None
    # near_node_ids = [node['id'] for node in nodes]
    for measurement_id, result_list in measurement_results:
        logging.debug('next result {}'.format(len(result_list)))
        for result in result_list:
            oldest_allowed_time = int(time.time()) - allowed_measurement_age
            if result.execution_time < oldest_allowed_time:
                continue

            result_rtt = result.min_rtt

            if result_rtt is None:
                continue
            elif result_rtt == -1:
                if temp_result_rtt is None:
                    temp_result_rtt = result_rtt
                if date_n is None or date_n < result.execution_time:
                    date_n = result.execution_time
            elif temp_result_rtt is None or result_rtt.min_rtt < temp_result_rtt.min_rtt:
                temp_result_rtt = result_rtt
                results.append(result)

    return temp_result_rtt
