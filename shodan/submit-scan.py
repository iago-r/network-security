#!/usr/bin/env python3

from shodan import Shodan

# Setup the Shodan API object
api = Shodan("23JnVloslnwzHEWAKzTXU2VEG27xCioo")

# Submit a scan request for 1 IP and 1 network range
scan = scan = api.scan({
    '200.233.189.132': [
        (5000, 'https'),
    ]
})

print(scan)
# shodan download --limit 100 scan-cecremge-5000https.json.gz scan:uwOh9JWw5peV5TLX
# {'count': 1, 'id': 'uwOh9JWw5peV5TLX', 'credits_left': 5053}
