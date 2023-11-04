#!/bin/bash

data=$(date +'%Y%m%d')

censys search --pages -1 --output CENSYS-UFMG.$data.json "ip: 150.164.0.0/16"
