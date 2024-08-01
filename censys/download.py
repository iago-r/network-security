#!/usr/bin/env python3

import argparse
import ipaddress
import json
import logging
import os
import pathlib
import sys
from typing import Optional


BASEURL = "https://search.censys.io/api/v1/data/"


def create_parser():
    desc = """Download Censys scan data"""
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument(
        "--dataset",
        dest="dataset",
        action="store",
        metavar="DATASET",
        type=str,
        required=False,
        help="Dataset path (see README) [%(default)s]",
        default="https://search.censys.io/api/v1/data/universal-internet-dataset-v2-ipv4",
    )

    parser.add_argument(
        "--start-date",
        dest="startdate",
        action="store",
        metavar="YYYY-MM-DD",
        type=str,
        required=True,
        help="First snapshot to download"
    )
    parser.add_argument(
        "--end-date",
        dest="enddate",
        action="store",
        metavar="YYYY-MM-DD",
        type=str,
        required=False,
        help="Last snapshot to download [download only first snapshot]"
        default=None,
    )

    parser.add_argument(
        "--api-file",
        dest="apifp",
        action="store",
        metavar="FILE",
        type=pathlib.Path,
        required=False,
        help="Path to file containing APIID and APIKEY [%(default)s]",
        default=pathlib.Path("~/.config/censys.apikey"),
    )
    # parser.add_argument(
    #     "--api-id",
    #     dest="apiid",
    #     action="store",
    #     metavar="STR",
    #     type=str,
    #     required=False,
    #     help="APIID to use when making requests [--keyfile]",
    # )
    # parser.add_argument(
    #     "--api-key",
    #     dest="apikey",
    #     action="store",
    #     metavar="STR",
    #     type=str,
    #     required=False,
    #     help="APIKEY to use when making requests [--keyfile]",
    # )
    return parser


def _read_apiid_apikey(path: pathlib.Path) -> tuple[str, str]:
    with open(path, encoding="utf8") as fd:
        apiid_str, apiid = fd.readline().strip().split("=")
        assert apiid_str == "APIID"
        apikey_str, apikey = fd.readline().strip().split("=")
        assert apikey_str == "APIKEY"
    return apiid, apikey


def _download_file_list(opts: argparse.Namespace) -> list[str]:
    r: requests.Response = requests.get(f"{BASEURL}/{opts.dataset}/{date.strftime('%Y%m%d')}", auth=(opts.apiid, opts.apikey),)
    r.raise_for_status()
    data = r.json()


def main():
    logging.basicConfig(level=logging.INFO)
    parser = create_parser()
    opts = parser.parse_args()

    filelist = _download_file_list(opts)



if __name__ == "__main__":
    sys.exit(main())
