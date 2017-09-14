#! /bin/sh

actualDate=`date +%s`
oldestDateAllowed=`expr ${actualDate} - 24 * 3600 * 30`

for filename in $@;
do
    bzcat ${filename} | jq -c '. | select(.timestamp >= ${oldestDateAllowed} and has("dst_addr")) | {timestamp: .timestamp, avg: .avg, dst_addr: .dst_addr, from: .from, min: .min, msm_id: .msm_id, type: .type, result: [.result[] | select(has("rtt")) | {rtt: .rtt}], proto: .proto, src_addr: .src_addr, ttl: .ttl, prb_id: .prb_id}' > /data/ripe_atlas/${filename:0:`expr ${#filename} - 4`}
done
