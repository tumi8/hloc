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
        -> typing.Generator[typing.Tuple[int, typing.List[RipeMeasurementResult]], None, None]:
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

            measurements.append(ripe_measurement)

        yield measurement_id, measurements


def check_measurements_for_nodes(measurement_ids: [int],
                                 nodes: [RipeAtlasProbe],
                                 ripe_slow_down_sema: mp.Semaphore,
                                 allowed_measurement_age: int) \
        -> typing.Optional[typing.List[MeasurementResult]]:
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
    temp_result = None
    date_n = None

    measurement_objs = []
    # near_node_ids = [node['id'] for node in nodes]
    for measurement_id, measurements in measurement_results:
        logging.debug('next result {}'.format(len(measurements)))
        for measurement in measurements:
            oldest_allowed_time = int(time.time()) - allowed_measurement_age
            if measurement.timestamp < oldest_allowed_time:
                continue

            measurement_objs.append(measurement)
            result_rtt = measurement.min_rtt

            if result_rtt is None:
                continue
            elif result_rtt == -1:
                if temp_result is None:
                    temp_result = measurement

                    if date_n is None or date_n < measurement.timestamp:
                        date_n = measurement.timestamp

            elif temp_result is None or result_rtt.min_rtt < temp_result.min_rtt:
                temp_result = measurement

    measurement_objs.remove(temp_result)
    measurement_objs.insert(0, temp_result)

    return temp_result
