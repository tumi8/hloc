#!/usr/bin/env bash

# 1st parameter: database name
# 2nd parameter: export directory

filedate=`date +%Y-%m-%d-%H-%M`
filedateUnix=`date +%s`
# 100 days of allowed measurement age (100 * 24 * 60 * 60)
allowedMeasurementAge=8640000
oldestDateAllowedUnix=`expr ${filedateUnix} - ${allowedMeasurementAge}`
oldestDateAllowed=`date --date "@${oldestDateAllowedUnix}" "+%Y-%m-%d %H:%M:%S"`

if [ -z $1 ] || [ ! -d $2 ]; then
    echo "a database name and an export directory is needed!"
    return 1
else
    curDir=`pwd`
    cd $2
    exportAbsolutDir=`pwd`
    cd ${curDir}

    filename="hloc-data-export-${filedate}.csv"
    psql -c "COPY (SELECT * from domainsWithDistanceRTTs(TIMESTAMP '${oldestDateAllowed}', NULL, false, false) as temp_table) TO '${exportAbsolutDir}/${filename}' CSV HEADER ENCODING 'utf-8';" $1
fi
