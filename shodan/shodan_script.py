
import os
import json
import sys

import shodan

output_folder = "scans"

def main(network):
    api_key = os.getenv("shodan_api_key")

    if not api_key:
        print("Please set the 'shodan_api_key' environment variable.")
        sys.exit(1)

    api = shodan.Shodan(api_key)

    try:
        search_results = api.search(network)

        os.makedirs(output_folder, exist_ok=True)

        filename = f"{network.replace('/', '_')}.json"
        filepath = os.path.join(output_folder, filename)

        with open(filepath, 'w') as file:
            json.dump(search_results, file)

    except shodan.APIError as e:
        print(f"Error: {e}")        

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} network")
        sys.exit(1)
    
    main(sys.argv[1])