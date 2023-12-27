import json
import sys

# Checks that the correct number of arguments is provided
if len(sys.argv) != 2:
    print("Use: python3 script.py data_censys.json")
    sys.exit(1)

censys_json = sys.argv[1]

with open(censys_json, 'r') as file:
  json_data = file.read()


data = json.loads(json_data)

OUTPUT = 'IPS.txt'

with open(OUTPUT, 'w') as arq:
  for ip in data:
    var = ip["ip"]
    arq.write(f"{var}\n")
