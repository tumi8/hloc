CREATE OR REPLACE FUNCTION domainsWithDistanceRTTs(oldestDateAllowed timestamp, youngestDateAllowed timestamp, excludeTracerouteMeasurements boolean, excludeCaidaMeasurements boolean) RETURNS TABLE (domain_id integer, domain_name varchar, ip_address inet, probe_id varchar, probe_location_lat float, probe_location_lon float, measurement_results_id integer, ripe_measurement_id INTEGER, measurement_timestamp timestamp, min_rtt float) AS $$
	WITH min_measurement_results as (
	SELECT tmp_tbl.id as id, tmp_tbl.ripe_measurement_id as ripe_measurement_id, tmp_tbl.probe_id as probe_id, tmp_tbl.destination_address as destination_address, tmp_tbl.timestamp as m_timestamp, tmp_tbl.rtt as rtt
	FROM (SELECT *, row_number() OVER (PARTITION BY destination_address ORDER BY rtt) as row_nr
		  FROM measurement_results
		  WHERE (timestamp > oldestDateAllowed or oldestDateAllowed IS NULL) and (timestamp < youngestDateAllowed or youngestDateAllowed IS NULL) and (not excludeTracerouteMeasurements or not from_traceroute) and (not excludeCaidaMeasurements or not measurement_result_type = 'caida_ark_measurement')
		  ) as tmp_tbl
	WHERE row_nr = 1 )
	SELECT domains.id as domain_id, domains.name as domain_name, (CASE WHEN domains.ipv4_address IS NULL THEN domains.ipv6_address ELSE domains.ipv4_address END) as ip_address, probes.probe_id as probe_id, measurement_location.lat as probe_location_lat, measurement_location.lon as probe_location_lon, min_measurement_results.id as min_measurement_results, min_measurement_results.ripe_measurement_id as ripe_measurement_id, min_measurement_results.m_timestamp as measurement_timestamp, min_measurement_results.rtt as min_rtt
	FROM domains join min_measurement_results on (domains.ipv4_address = min_measurement_results.destination_address OR domains.ipv6_address = min_measurement_results.destination_address)
		join probes on (probes.id = min_measurement_results.probe_id)
		join locations measurement_location on (measurement_location.id = probes.location_id)
	$$
LANGUAGE SQL;
