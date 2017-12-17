#!/usr/bin/env sh

# $1 is the database name
# $2 is the path to the rdns file
# $3 is the hloc directory
# $4 path to python environment

if [ -z $1 ] || [ -z $2 ] || [ -z $3 ] || [ ! -d $4 ]; then
    echo "a databasename, the rdns file, the hloc directory, and the python environment directory is needed! Aborting!"
    return 1
else
    echo "if asked to recreate the db answer with yes (y)"
    source $4/bin/activate

    cd $3

    logPath="logs"
    if [ ! -d ${logPath} ]; then
        mkdir ${logPath}
    fi

    python3 -m hloc.scripts.codes_parser --database-name $1 -ao /data/old-vm/data/rdns-parse/pages_offline/ -le "/data/location-data/locodePart{}.csv" -c /data/location-data/clli-lat-lon.txt -g /data/location-data/cities1000.txt -e /data/location-data/iata_metropolitan.txt -m 100 -p 100000 -l ${logPath}/codes-parsing -ll DEBUG -d

    if [ -e $2 ]; then
        python3 -m hloc.scripts.ipdns_parser $2 --database-name $1 --number-processes 8 -t /data/location-data/tlds.txt --isp-ip-filter -l ${logPath}/dns-parsing -ll DEBUG
    else
        echo "the file ", $2, " does not exist"
        return 2
    fi
fi
