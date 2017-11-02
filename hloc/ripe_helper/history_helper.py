"""

"""

import bz2
import datetime
import json
import logging
import multiprocessing as mp
import random
import time
import typing
import collections

import requests
import ripe.atlas.cousteau as ripe_atlas

from hloc.db_utils import probe_for_id, location_for_coordinates
from hloc.models import RipeMeasurementResult, RipeAtlasProbe, MeasurementResult


def __get_measurements_for_nodes(measurement_ids: [int],
                                 ripe_slow_down_sema: mp.Semaphore,
                                 near_nodes: [RipeAtlasProbe],
                                 allowed_measurement_age: int) \
        -> typing.Generator[typing.Tuple[int, typing.List[RipeMeasurementResult]], None, None]:
    """Loads all results for all measurements if they are less than a year ago"""

    node_dct = {}
    for node in near_nodes:
        node_dct[node.probe_id] = node.id

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
            if not success and 'error' in result_list and 'status' in result_list[
                    'error'] and 'code' in result_list['error'] and result_list['error'][
                    'status'] == 406 and result_list['error']['code'] == 104:
                retries = 5
                break
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
            ripe_measurement.probe_id = node_dct[str(res['prb_id'])]

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
            if measurement.timestamp.timestamp() < oldest_allowed_time:
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

            elif temp_result is None or result_rtt < temp_result.min_rtt:
                temp_result = measurement

    if temp_result:
        measurement_objs.remove(temp_result)
        measurement_objs.insert(0, temp_result)

    return measurement_objs


def get_archive_probes(db_session) -> typing.Dict[str, RipeAtlasProbe]:
    ProbeRFC1918Tuple = collections.namedtuple('ProbeRFC1918Tuple', ['probe', 'is_rfc1918'])

    yesterday = datetime.date.today() - datetime.timedelta(days=2)
    probe_archive_url = "https://ftp.ripe.net/ripe/atlas/probes/archive/" + \
                        yesterday.strftime('%Y/%m/%Y%m%d') + ".json.bz2"

    ripe_response = requests.get(probe_archive_url)

    if ripe_response.status_code != 200:
        ripe_response.raise_for_status()

    probe_str = bz2.decompress(ripe_response.content)
    probes_dct_list = json.loads(probe_str.decode())['objects']
    return_dct = {}

    for probe_dct in probes_dct_list:
        if probe_dct['total_uptime'] > 0 and probe_dct['latitude'] and probe_dct['longitude']:
            probe = __parse_probe(probe_dct, db_session)
            return_dct[str(probe.probe_id)] = ProbeRFC1918Tuple(
                probe=probe,
                is_rfc1918='system-ipv4-rfc1918' in [tag['slug'] for tag in probe_dct['tags']])

    db_session.add_all([probe for probe, _ in return_dct.values()])
    db_session.commit()

    return return_dct


def __parse_probe(probe_dct: typing.Dict[str, typing.Any], db_session) -> RipeAtlasProbe:
    probe_id = str(probe_dct['id'])
    probe_db_obj = probe_for_id(probe_id, db_session)

    if probe_db_obj and \
            probe_db_obj.location.gps_distance_haversine_plain(
                probe_dct['latitude'], probe_dct['longitude']) < 2:
        return probe_db_obj

    location = location_for_coordinates(probe_dct['latitude'],
                                        probe_dct['longitude'],
                                        db_session)

    probe_db_obj = RipeAtlasProbe(probe_id=probe_id, location=location)

    return probe_db_obj
