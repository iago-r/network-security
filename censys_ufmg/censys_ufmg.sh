#!/bin/bash
set -eu

datetime=$(date +'%Y%m%d')

# Scan
censys search --pages -1 --output CENSYS-UFMG.$datetime.json "ip: 150.164.0.0/16" 

# Compress file
bzip2 CENSYS-UFMG.$datetime.json

# Moving file to directory in storage
mv CENSYS-UFMG.$datetime.json.bz2 /home/storage/censys_UFMG/

# Done !
echo "Censys job downloaded and compressed successfully!!"
