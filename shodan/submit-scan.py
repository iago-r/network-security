#!/usr/bin/env python3

from shodan import Shodan

# Setup the Shodan API object
api = Shodan("load_api_here")

# Submit a scan request for 1 IP and 1 network range
scan = scan = api.scan({
    '200.233.189.132': [
        (5000, 'https'),
    ]
})

print(scan)
