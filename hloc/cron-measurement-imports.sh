#!/usr/bin/env sh

archivepathripe="/mnt/alcatraz/ra-bulk/"

archivepathcaida="/mnt/alcatraz/caida-itdk/prefix-probing"

cd /data/hloc
python3 -m hloc.scripts.importer.delete_measurements --days-in-past 90 --database-name hloc-measurements -l cron-delete-measurements.log -ll DEBUG
python3 -m hloc.scripts.importer.parse_ripe_archive $archivepathripe --number-processes 8 --days-in-past 60 --database-name hloc-measurements -l cron-ripe-import.log -ll DEBUG
python3 -m hloc.scripts.importer.parse_caida_archive $archivepathcaida --number-processes 8 --days-in-past 60 --database-name hloc-measurements -l cron-caida-import.log -ll DEBUG

echo "import complete"
