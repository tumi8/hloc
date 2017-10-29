#!/usr/bin/env bash

filedate=`date +%Y-%m-%d-%H-%M`
# 100 days of allowed measurement age (100 * 24 * 60 * 60
allowedMeasurementAge=8640000
oldestDateAllowed=`date -v-${allowedMeasurementAge}S +%Y-%m-%d-%H-%M-%S`

# $1 is the database name

if [ -z $1 ]; then
    echo "a databasename is needed!"
    return 1
else
    filename="hloc-data-export-${filedate}.csv"
    psql -c "COPY (SELECT * from domainsWithDistanceRTTs(TIMESTAMP '${oldestDateAllowed}', NULL, false, false) as temp_table) TO '$filename' WITH FORMAT 'csv', HEADER true, ENCODING 'utf-8';" $1
fi
