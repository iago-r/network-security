#!/usr/bin/env python3

from pathlib import Path
import sys

import requests


KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def download_kev_database(outfp: Path) -> dict:
    response = requests.get(KEV_JSON_URL)
    response.raise_for_status()
    outfp.write_text(response.text)
    return response.json()


if __name__ == "__main__":
    download_kev_database(Path(sys.argv[1]))
