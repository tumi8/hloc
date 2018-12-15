#!/bin/bash

# 1st parameter: database name
# 2nd parameter: ripe atlas API key
# 3rd parameter: path to hloc installation
# 4th parameter: path to python environment
# 5th parameter (optional): a path to a file with ips

filedate=`date +%Y-%m-%d-%H-%M`
# 180 days of allowed measurement age
allowedMeasurementAge=15552000

if [ -z $1 ] || [ -z $2 ] || [ ! -d $3 ] || [ ! -d $4 ]; then
    echo "provide the database name, the RIPE Atlas API key, the hloc directory, and the python environment directory! Aborting!"
    exit 1
else
    source $4/bin/activate

    cd $3

    logPath="logs"
    if [ ! -d ${logPath} ]; then
        mkdir ${logPath}
    fi

    if [ ! -f "/var/cache/hloc/ripe_probes.cache" ] || [ `psql -d $1 -U hloc -tc "SELECT count(*) from probes"` -eq 0 ]; then
        ./hloc/cache_ripe_probes.sh $3 $1 $4
    fi

    if [ $# -eq 5 ] && [ -e $5 ]; then
        python3 -m hloc.scripts.validate --number-processes 10 --ripe-request-limit 30 --ripe-request-burst-limit 50 --measurement-limit 100 --allowed-measurement-age ${allowedMeasurementAge} --buffer-time 0 --measurement-strategy aggressive --api-key $2 --include-ip-encoded --use-efficient-probes --probes-per-measurement 1 --measurement-packets 1 --database-name $1 --ip-filter-file $5 -l ${logPath}/validate-multi.log -ll DEBUG
    elif [ $# -eq 4 ]; then
        python3 -m hloc.scripts.validate --number-processes 10 --ripe-request-limit 30 --ripe-request-burst-limit 50 --measurement-limit 100 --allowed-measurement-age ${allowedMeasurementAge} --buffer-time 0 --measurement-strategy aggressive --api-key $2 --include-ip-encoded --use-efficient-probes --probes-per-measurement 1 --measurement-packets 1 --database-name $1 --endless-measurements --random-domains -l ${logPath}/validate-multi.log -ll DEBUG
    else
        echo "Either not the correct amount of properties was given or IP-List file could not be found!"
    fi
fi
