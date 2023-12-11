#!/bin/bash


############################################
#
# Script to download Censys snapshots
# 
# Before run it, please define an 
# environment variable CENSYS_API and 
# CENSYS_API_SECRET to set your permissions
#
############################################

PS3='Please enter your choice: '
options=("list" "latest" "specific" "quit")
select opt in "${options[@]}"
do
    case $opt in
        "list")
            echo "Listing available snapshots"
	    curl -g -s -X 'GET' 'https://search.censys.io/api/v1/data/universal-internet-dataset-v2-ipv4' -H 'Accept: application/json' --user "$CENSYS_API_ID:$CENSYS_API_SECRET" | jq -r ".results.historical | map(.id)"
            ;;
        "latest")
            echo "Getting latest snapshot"
	    url1=$(curl -g -s -X 'GET' 'https://search.censys.io/api/v1/data/universal-internet-dataset-v2-ipv4' -H 'Accept: application/json' --user "$CENSYS_API_ID:$CENSYS_API_SECRET" | jq -r ".results.latest.details_url")
	    break
            ;;
        "specific")
	    echo -n "Enter the snapshot id: "
            read snapshot_id
	    url1="https://search.censys.io/api/v1/data/universal-internet-dataset-v2-ipv4/$snapshot_id"
	    break 
            ;;
        "quit")
            exit 1
            ;;
        *) echo "invalid option $REPLY";;
    esac
done

snapshot_date=$(basename $url1)
echo "Latest snapshot: $snapshot_date";

if [ -d ./original/$snapshot_date ]; then
  echo "Snapshot directory already exists."
  exit 1
fi

# Para o id mais atual, recupera a lista de urls para download
var_json2=$(curl -g -s -X 'GET' $url1 -H 'Accept: application/json' --user "$CENSYS_API_ID:$CENSYS_API_SECRET");
# Imprime o tamanho em bytes total do dataset
echo "Total size (in bytes): " $(echo "$var_json2" | jq -r ".total_size") ;

mkdir -p ./original/$snapshot_date
cd ./original/$snapshot_date 

for hash in $(echo "$var_json2" | jq -r '.files | keys[] as $k | "\($k);\(.[$k].compressed_md5_fingerprint);\(.[$k].download_path)"'); do
    IFS=";" read -r var1 var2 var3 <<< $hash

    while
	 echo "Downloading: $var3"
	 curl  --retry 10 -f --retry-all-errors --retry-delay 5 -L -O  $var3 -H 'Accept: application/json' --user "$CENSYS_API_ID:$CENSYS_API_SECRET"  
         md5_hash=$(md5sum $var1)
        [[ "$md5_hash" != "$var2"* ]]
        do true;  done

done
