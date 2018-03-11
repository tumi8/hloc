#!/bin/bash

if [ -z $1 ] || [ -z $2 ] || [ ! -d $3 ]; then
    echo "provide path to hloc directory, the database name, and the python environment! Aborting!"
    return 1
else
    source $3/bin/activate

    cd $1

    logPath="logs"
    if [ ! -d ${logPath} ]; then
        mkdir ${logPath}
    fi

    if ! python3 -m hloc.scripts.importer.get_ripe_probes $2 --ripe-requests-per-second 40 -l ${logPath}/cron-probe-caching.log -ll DEBUG; then
        echo "probe caching had an error"
        exit 1
    fi

    echo "probe caching complete"
fi
