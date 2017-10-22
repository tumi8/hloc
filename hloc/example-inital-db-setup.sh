#!/usr/bin/env sh

if [ -z $1 ] || [ -z $2 ] || [ -z $3 ]; then
    echo "a databasename and the ip version is needed!"
    return 1
else
    echo "if asked to recreate the db answer with yes (y)"
    python3 -m hloc.scripts.codes_parser --database-name $1 -ao /data/old-vm/data/rdns-parse/pages_offline/ -le "/data/location-data/locodePart{}.csv" -c /data/location-data/clli-lat-lon.txt -g /data/location-data/cities1000.txt -e /data/location-data/iata_metropolitan.txt -m 100 -p 100000 -ll DEBUG -d

    if [ -e $2 ]; then
        python3 -m hloc.scripts.ipdns_parser $2 --database-name $1 --number-processes 8 -t /data/location-data/tlds.txt --isp-ip-filter --ip-version $3
    else
        echo "the file ", $2, " does not exist"
        return 2
    fi
fi