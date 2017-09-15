#!/bin/bash

actualDate=`date +%s`
oldestDateAllowed=`expr ${actualDate} - 24 \* 3600 \* 30`
filterString='. | select(.timestamp >= '"${oldestDateAllowed}"' and has("dst_addr")) | {timestamp: .timestamp, avg: .avg, dst_addr: .dst_addr, from: .from, min: .min, msm_id: .msm_id, type: .type, result: [.result[] | select(has("result")) | {result: [.result[] | select(has("rtt") and has("from") and has("err") == false) | {rtt: .rtt, ttl: .ttl, from: .from}], hop: .hop}], proto: .proto, src_addr: .src_addr, ttl: .ttl, prb_id: .prb_id}'

for filename in $@;
do
    bzcat ${filename} | jq -c "${filterString}" > /data/ripe-atlas/${filename:22:`expr ${#filename} - 22 - 4`}
done
