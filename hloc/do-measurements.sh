#!/usr/bin/env sh

# 1st parameter: database name
# 2nd parameter: ripe atlas API key
# 3rd parameter (optional): a path to a file with ips

filedate=`date +%Y-%m-%d-%H-%M`
# 180 days of allowed measurement age
allowedMeasurementAge=15552000

if [ $# -eq 3 ] && [ -e $3 ]; then
    python3 -m hloc.scripts.validate --number-processes 8 --ripe-request-limit 30 --ripe-request-burst-limit 50 --measurement-limit 100 --allowed-measurement-age $allowedMeasurementAge ---buffer-time 0 --measurement-strategy aggressive --api-key $2 --include-ip-encoded --use-efficient-probes --probes-per-measurement 3 --measurement-packets 4 --database-name $1 --ip-filter-file $3 -l validate-${filedate}-multi.log -ll DEBUG
elif [ $# -eq 2 ]; then
    python3 -m hloc.scripts.validate --number-processes 8 --ripe-request-limit 30 --ripe-request-burst-limit 50 --measurement-limit 100 --allowed-measurement-age $allowedMeasurementAge ---buffer-time 0 --measurement-strategy aggressive --api-key $2 --include-ip-encoded --use-efficient-probes --probes-per-measurement 3 --measurement-packets 4 --database-name $1 --endless-measurements --random-domains -l validate-${filedate}-multi.log -ll DEBUG
else
    echo "Either not the correct amount of properties was given or IP-List file was not found!"
fi
