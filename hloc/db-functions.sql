
CREATE OR REPLACE FUNCTION earthRadius() RETURNS numeric
    AS 'SELECT 6371.0'
    LANGUAGE SQL;

CREATE OR REPLACE FUNCTION gpsDistanceRadiansHaversine(lat1 float, lon1 float, lat2 float, lon2 float) RETURNS float
    AS '
    SELECT
      2 * atan2(
      sqrt(    pow(sin((lat2 - lat1) / 2), 2) + cos(lat1) * cos(lat2) * pow(sin((lon2 - lon1) / 2), 2)),
      sqrt(1 - pow(sin((lat2 - lat1) / 2), 2) + cos(lat1) * cos(lat2) * pow(sin((lon2 - lon1) / 2), 2))
      )
      * earthRadius()'
    LANGUAGE SQL
    RETURNS NULL on NULL INPUT;

CREATE OR REPLACE FUNCTION gpsDistance(lat1 float, lon1 float, lat2 float, lon2 float) RETURNS float
    AS 'SELECT gpsDistanceRadiansHaversine(radians(lat1), radians(lon1), radians(lat2), radians(lon2))'
    LANGUAGE SQL
    RETURNS NULL on NULL INPUT;

CREATE OR REPLACE FUNCTION minRTTsForDomains(oldestDateAllowed timestamp, youngestDateAllowed timestamp, excludeTracerouteMeasurements boolean, excludeCaidaMeasurements boolean) RETURNS TABLE (measurement_id bigint, ripe_measurement_id INTEGER, probe_id integer, ip_address inet, measurement_timestamp timestamp, measurement_type varchar, from_traceroute bool, rtt float, domain_id integer, domain_name varchar)
    AS $$
      SELECT measurement_id, ripe_measurement_id, probe_id, ip_address, measurement_timestamp, measurement_type::varchar, from_traceroute, rtt, domain_id, domain_name
            FROM (
                SELECT measurement_results.id as measurement_id, ripe_measurement_id as ripe_measurement_id, probe_id, destination_address as ip_address, timestamp as measurement_timestamp, measurement_result_type as measurement_type, from_traceroute, rtt as rtt, row_number() OVER (PARTITION BY destination_address ORDER BY rtt) as row_nr, domains.id as domain_id, domains.name as domain_name
                FROM measurement_results join domains on (
                    (measurement_results.destination_address = domains.ipv4_address OR
                      measurement_results.destination_address = domains.ipv6_address)
                    AND (timestamp > oldestDateAllowed OR oldestDateAllowed IS NULL)
                    AND (NOT excludeTracerouteMeasurements OR NOT from_traceroute)
                    AND (NOT excludeCaidaMeasurements OR NOT measurement_result_type = 'caida_ark_measurement'))
                ) as measurement_tbl
            WHERE row_nr = 1
      $$
      LANGUAGE SQL PARALLEL SAFE;

CREATE OR REPLACE FUNCTION domainLocationHintsWithDistanceRTTs(oldestDateAllowed timestamp, youngestDateAllowed timestamp, excludeTracerouteMeasurements boolean, excludeCaidaMeasurements boolean) RETURNS TABLE (domain_id integer, domain_name varchar, ip_address inet, location_hints_id integer, hint_location_code varchar, location_hint_type varchar, hint_location_id varchar, hint_location_lat float, hint_location_lon float, probe_id varchar, probe_location_lat float, probe_location_lon float, measurement_results_id bigint, ripe_measurement_id INTEGER, measurement_timestamp INTEGER, measurement_type varchar, from_traceroute bool, min_rtt_ms float, distance_km float)
    AS $$
        SELECT min_measurement_results.domain_id as domain_id, min_measurement_results.domain_name as domain_name, min_measurement_results.ip_address as ip_address, location_hints.id as location_hints_id, location_hints.code as hint_location_code, location_hints.code_type::varchar as hint_location_type, hint_location.id as hint_location_id, hint_location.lat as hint_location_lat, hint_location.lon as hint_location_lon, probes.probe_id as probe_id, measurement_location.lat as probe_location_lat, measurement_location.lon as probe_location_lon, min_measurement_results.measurement_id as measurement_results_id, min_measurement_results.ripe_measurement_id as ripe_measurement_id, extract(epoch from min_measurement_results.measurement_timestamp)::INTEGER as measurement_timestamp, min_measurement_results.measurement_type, min_measurement_results.from_traceroute, min_measurement_results.rtt as min_rtt_ms, gpsDistance(hint_location.lat, hint_location.lon, measurement_location.lat, measurement_location.lon) as distance_km
        FROM minRTTsForDomains(oldestDateAllowed, youngestDateAllowed, excludeTracerouteMeasurements, excludeCaidaMeasurements) as min_measurement_results join domain_to_labels d_t_label on (min_measurement_results.domain_id = d_t_label.domain_id)
            join domain_labels on (domain_labels.id = d_t_label.domain_label_id)
            join location_hint_labels loc_hint on (domain_labels.id = loc_hint.domain_label_id)
            join location_hints on (location_hints.id = loc_hint.location_hint_id)
            join locations hint_location on (location_hints.location_id=hint_location.id)
            join probes on (probes.id = min_measurement_results.probe_id)
            join locations measurement_location on (measurement_location.id = probes.location_id)
        $$
    LANGUAGE SQL PARALLEL SAFE;

CREATE OR REPLACE FUNCTION domainLocationHintsWithDistanceRTTsAnnotated(oldestDateAllowed timestamp, youngestDateAllowed timestamp, excludeTracerouteMeasurements boolean, excludeCaidaMeasurements boolean) RETURNS TABLE (domain_id integer, domain_name varchar, ip_address inet, location_hints_id integer, hint_location_code varchar, location_hint_type varchar, hint_location_id varchar, hint_location_lat float, hint_location_lon float, probe_id varchar, probe_location_lat float, probe_location_lon float, measurement_results_id bigint, ripe_measurement_id INTEGER, measurement_timestamp INTEGER, measurement_type varchar, from_traceroute bool, min_rtt_ms numeric, distance_km float, possible bool)
    AS $$
        SELECT results.domain_id, results.domain_name, results.ip_address, results.location_hints_id, results.hint_location_code, results.location_hint_type, results.hint_location_id, results.hint_location_lat, results.hint_location_lon, results.probe_id, results.probe_location_lat, results.probe_location_lon, results.measurement_results_id, results.ripe_measurement_id, results.measurement_timestamp, results.measurement_type, results.from_traceroute, round(results.min_rtt_ms::numeric, 2) as min_rtt_ms, distance_km, results.min_rtt_ms * 100 > distance_km as possible
        FROM domainLocationHintsWithDistanceRTTs(oldestDateAllowed, youngestDateAllowed, excludeTracerouteMeasurements, excludeCaidaMeasurements) as results
        ORDER BY ip_address
        $$
    LANGUAGE SQL PARALLEL SAFE;