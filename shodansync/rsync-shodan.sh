#!/bin/bash
set -eu

remote=/var/data/shodan/
local=/home/datasets/survey/downloaded/
logfile=$local/$(date +%s).rsync.log
touch logfile
rsync --archive --progress --log-file=$logfile koloth-rsync:$remote/ $local/
