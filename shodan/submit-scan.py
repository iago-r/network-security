#!/usr/bin/env python3

import os
import sys

from shodan import Shodan

TARGETS_FILE = "hostnames.txt"

shodan_api_key = os.getenv("shodan_api_key")
if shodan_api_key is None:
    print("Please set the 'shodan_api_key' env variable")
    sys.exit(1)

# Setup the Shodan API object
api = Shodan(shodan_api_key)

# Submit a scan request for 1 IP and 1 network range
# docs: https://shodan.readthedocs.io/en/latest/api.html

with open(TARGETS_FILE, encoding="utf8") as fd:
    ips = [line.strip() for line in fd]

scan = api.scan(ips)
print(scan)
# shodan download --limit 100 scan-cecremge-5000https.json.gz scan:uwOh9JWw5peV5TLX
# {'count': 1, 'id': 'uwOh9JWw5peV5TLX', 'credits_left': 5053}
