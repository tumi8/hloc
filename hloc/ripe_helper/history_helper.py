"""

"""

import multiprocessing as mp
import random
import typing
import time
import logging

import ripe.atlas.cousteau as ripe_atlas

from hloc.models import RipeMeasurementResult,RipeAtlasProbe, LocationInfo, MeasurementResult


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


def check_measurements_for_nodes(measurement_ids: [int],
                                 location: LocationInfo,
                                 nodes: [RipeAtlasProbe],
                                 results: [MeasurementResult],
                                 ripe_slow_down_sema: mp.Semaphore,
                                 allowed_measurement_age: int) \
        -> typing.Optional[MeasurementResult]:
    """
    Check the measurements list for measurements from near_nodes
    :rtype: (float, dict)
    """
    if not measurement_ids:
        return None

    measurement_results = __get_measurements_for_nodes(measurement_ids,
                                                       ripe_slow_down_sema,
                                                       nodes,
                                                       allowed_measurement_age)
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
