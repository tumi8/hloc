#!/usr/bin/env sh

archivepathripe="/mnt/alcatraz/ra-bulk/"

archivepathcaida="/mnt/alcatraz/caida-itdk/prefix-probing"

# all measurements older then 90 days will be deleted
nonDeletedPastDays=90

# last 60 days will be imported
importDays=60

if [ -z $1 ] || [ -z $2 ] || [ ! -D $3 ]; then
    echo "provide path to hloc directory, the database name, and the python environment! Aborting!"
    return 1
else
    source $3/bin/activate

    cd $1

    logPath="logs"
    if [ ! -D ${logPath} ]; then
        mkdir ${logPath}
    fi

    python3 -m hloc.scripts.importer.delete_measurements --days-in-past ${nonDeletedPastDays} --database-name $2 -l ${logPath}/cron-delete-measurements.log -ll DEBUG
    python3 -m hloc.scripts.importer.parse_ripe_archive ${archivepathripe} --number-processes 8 --days-in-past ${importDays} --database-name $2 -l ${logPath}/cron-ripe-import.log -ll DEBUG
    python3 -m hloc.scripts.importer.parse_caida_archive ${archivepathcaida} --number-processes 8 --days-in-past ${importDays} --database-name $2 -l ${logPath}/cron-caida-import.log -ll DEBUG

    echo "import complete"
fi
