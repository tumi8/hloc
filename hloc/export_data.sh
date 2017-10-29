#!/usr/bin/env bash

# 1st parameter: database name
# 2nd parameter: export directory

filedate=`date +%Y-%m-%d-%H-%M`
# 100 days of allowed measurement age (100 * 24 * 60 * 60
allowedMeasurementAge=8640000
oldestDateAllowed=`date -v-${allowedMeasurementAge}S +%Y-%m-%d-%H-%M-%S`

if [ -z $1 ] || [ -z $2 ]; then
    echo "a database name and an export directory is needed!"
    return 1
else
    filename="hloc-data-export-${filedate}.csv"
    psql -c "COPY (SELECT * from domainsWithDistanceRTTs(TIMESTAMP '${oldestDateAllowed}', NULL, false, false) as temp_table) TO '${2}/${filename}' WITH FORMAT 'csv', HEADER true, ENCODING 'utf-8';" $1
fi
