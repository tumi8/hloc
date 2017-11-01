#!/usr/bin/env sh

archivepathripe="/mnt/alcatraz/ra-bulk/"

archivepathcaida="/mnt/alcatraz/caida-itdk/prefix-probing"

# all measurements older then 90 days will be deleted
nonDeletedPastDays=90

# last 60 days will be imported
importDays=60

if [ -z $1 ] && [ -z $2 ]; then
    echo "provide path to hloc directory and the database name!"
    return 1
else
    cd $1

    python3 -m hloc.scripts.importer.delete_measurements --days-in-past $nonDeletedPastDays --database-name $2 -l cron-delete-measurements.log -ll DEBUG
    python3 -m hloc.scripts.importer.parse_ripe_archive $archivepathripe --number-processes 8 --days-in-past $importDays --database-name $2 -l cron-ripe-import.log -ll DEBUG
    python3 -m hloc.scripts.importer.parse_caida_archive $archivepathcaida --number-processes 8 --days-in-past $importDays --database-name $2 -l cron-caida-import.log -ll DEBUG

    echo "import complete"
fi
