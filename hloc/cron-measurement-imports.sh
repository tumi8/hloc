#!/bin/bash

archivepathripe="/mnt/alcatraz/ra-bulk-new/"

archivepathcaidaipv4="/mnt/alcatraz/caida-itdk-new/datasets/topology/ark/ipv4/prefix-probing"
archivepathcaidaipv6="/mnt/alcatraz/caida-itdk-new/datasets/topology/ark/ipv6/probe-data"

# all measurements older then 100 days will be deleted
nonDeletedPastDays=100

# last 60 days will be imported
importDays=5


if [ -z $1 ] || [ -z $2 ] || [ ! -d $3 ]; then
    echo "provide path to hloc directory, the database name, and the python environment! Aborting!"
    exit 1
else
    (
        if ! flock -e -n 200; then
            echo "cron import already running not starting"
            exit 0
        fi

        source $3/bin/activate

        cd $1

        logPath="logs"
        if [ ! -d ${logPath} ]; then
            mkdir ${logPath}
        fi

        if [ ! -f "/var/cache/hloc/ripe_probes.cache" ]; then
            if ! ./hloc/cache_ripe_probes.sh $1 $2 $3; then
                exit 1
            fi
        fi

        python3 -m hloc.scripts.importer.delete_measurements --days-in-past ${nonDeletedPastDays} --database-name $2 -l ${logPath}/cron-delete-measurements.log -ll DEBUG &
        if ! python3 -m hloc.scripts.importer.parse_ripe_archive ${archivepathripe} --number-processes 4 --days-in-past ${importDays} --database-name $2 -l ${logPath}/cron-ripe-import.log -ll DEBUG; then
            echo "error while parsing ripe data"
            exit 1
        fi
        if ! python3 -m hloc.scripts.importer.parse_caida_archive ${archivepathcaidaipv4} --number-processes 4 --days-in-past ${importDays} --database-name $2 -l ${logPath}/cron-caida-import.log -ll DEBUG; then
            echo "error while parsing caida v4 data"
            exit 1
        fi
        if ! python3 -m hloc.scripts.importer.parse_caida_archive ${archivepathcaidaipv6} --number-processes 4 --days-in-past ${importDays} --database-name $2 -l ${logPath}/cron-caida-import.log -ll DEBUG; then
            echo "error while parsing caida v6 data"
            exit 1
        fi

        echo "import successfully completed"
    ) 200>/tmp/hloc-import.lock
fi
