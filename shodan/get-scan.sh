#!/bin/bash
set -eu

KEY=$(cat "$HOME/.config/secrets/shodan-italocunha.apikey")

while read -r scanid ; do
    curl -X GET -o "scan-$scanid.json" \
            "https://api.shodan.io/shodan/scan/$scanid?key=$KEY"
done < scanids.txt
