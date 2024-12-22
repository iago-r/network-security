#!/bin/bash
set -eu

INPUTDIR=~/git/kiron/data/blocks
OUTDIR=~/git/kiron/data/blocks/shodan/cloud-ips
SHODAN_IP_LIMIT=128

mkdir -p "$OUTDIR"

orig=$(cat $INPUTDIR/oi*br/cloud-ips.txt | wc -l)
sort -u $INPUTDIR/oi*br/cloud-ips.txt > $OUTDIR/cloud-ips.txt
echo "Original IPs: $orig"
echo "Unique IPs: $(wc -l < "$OUTDIR/cloud-ips.txt")"

while read -r ip ; do
    outfile=$OUTDIR/${ip//./_}
    query="ip:$ip"
    if [[ -s $outfile.json.gz ]] ; then
        echo "Skipping query for $outfile"
    fi
    shodan download --limit $SHODAN_IP_LIMIT $outfile $query
done < $OUTDIR/cloud-ips.txt
