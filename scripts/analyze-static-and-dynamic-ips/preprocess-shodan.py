#!/usr/bin/env python3

# Needed for analysis
import os
import bz2
import json
import datetime as dt
import multiprocessing
from itertools import repeat
from collections import defaultdict

# Code quality
import pickle
import logging
import argparse

# Code consistency
from typing import Any, Callable, Optional
from pydantic import BaseModel, ValidationError

# DynMap timeseries definition
from dynmap import IpTimeSeries


# Expected scan data format from Shodan .json or .json.bz2 files
class ShodanScanData(BaseModel):
    scan: dict[Any, Any]


# Expected ModuleData class
class ModuleDataModel(BaseModel):
    alias: str
    moduleNames: list[str]
    fingerprintFieldPath: str
    domainFieldPath: str
    extractorFn: Optional[Callable[[str], str]]


# Path used in fingerprint and domain field
FieldPath = list[str]
"""
Path to a fingerprint or domain field after splitting the original path by dots
"""


# Configurable module data for Shodan
class ModuleData:
    """
    Represents a supported module for Shodan scans.

    Please see initSupportedModules() for guidance on how to add support for new modules.
    """

    def __init__(
        self,
        alias: str,
        moduleNames: list[str],
        fingerprintFieldPath: str,
        domainFieldPath: str,
        extractorFn: Optional[Callable[[str], str]] = None,
    ):
        # Check
        try:
            ModuleDataModel(
                alias=alias,
                moduleNames=moduleNames,
                fingerprintFieldPath=fingerprintFieldPath,
                domainFieldPath=domainFieldPath,
                extractorFn=extractorFn,
            )
        except ValidationError as ve:
            errors: str = ""

            for e in ve.errors():
                errors += f"'{e['loc'][0]}', found {e['input']}, expected {e['type']}\n"

            logging.error(
                f"Unable to initialize ModuleData. The following parameters don't match the expected structure:\n{''.join(errors)} Aborted"
            )
            exit(1)

        # Assign
        self.alias: str = alias
        self.moduleNames: set[str] = moduleNames
        self.fingerprintField: FieldPath = fingerprintFieldPath.split(sep=".")
        self.domainField: FieldPath = domainFieldPath.split(sep=".")
        self.fingerprintExtractor: Optional[Callable[[str], str]] = extractorFn


def initParser(supportedModules: dict[str, ModuleData]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyzes IP addresses from a set of Shodan scans and extracts input data for DynMap."
    )

    parser.add_argument(
        "shodanDir",
        metavar="shodan-dir",
        type=str,
        help="directory with a collection of Shodan daily scans (each as a .json or .json.bz2 file)",
    )

    parser.add_argument(
        "targetModule",
        metavar="target-module",
        type=str,
        choices=supportedModules.keys(),
        help=f"Shodan module to be analyzed. Available options: {', '.join(supportedModules.keys())}",
    )

    parser.add_argument(
        "-c",
        "--cache-folder",
        type=str,
        dest="cacheFolder",
        action="store",
        default="cache",
        help="folder to store processed input data. (default: %(default)s)",
    )

    parser.add_argument(
        "-f",
        "--logfile",
        type=str,
        dest="logfile",
        action="store",
        default=None,
        help="file to store log outputs. If not specified, logs will be printed on screen",
    )

    parser.add_argument(
        "-l",
        "--loglevel",
        type=str,
        dest="loglevel",
        metavar="LOGLEVEL",
        action="store",
        choices=["DEBUG", "INFO", "WARN", "ERROR", "FATAL"],
        default="INFO",
        help="log level. Available options: DEBUG, INFO, WARN, ERROR, FATAL (default: %(default)s)",
    )

    return parser


def extractDomainFromSSH(domains: list[str]) -> str | None:
    """
    Extracts a domain from an SSH scan.

    Parameters
    ----------
    `domains`: list of domains found in the scan

    Returns
    -------
    `domain`: extracted domain or None if not found
    """

    # Domains is a string somehow, Shodan should return a list
    if isinstance(domains, str):
        return domains

    # SSH scans may have multiple domains found by Shodan
    if len(domains) > 0:
        # For the sake of simplicity, we sort and then return the first domain
        domains.sort()
        return domains[0]

    return None


def initSupportedModules() -> dict[str, ModuleData]:
    """
    Initializes a dictionary containing `ModuleData` for all supported modules.

    This way we can extract data from Shodan scans regardless of the module used.

    All modules must have:

    `alias`:                 used for argument parsing (so user can select a module)

    `module names`:          used to filter modules from shodan (multiple names are supported)

    `fingerprint field`:     used to select a fingerprint from the respective modules (nested path separated by dots)

    `domain field`:          used to select a domain name from the respective modules (nested path separated by dots)

    `fingerprint extractor:` function used to parse/extract the fingerprint from the selected field (optional)

    It is up to the user to add support for modules, please refer to the `https` and `ssh` implementations for guidance

    Returns
    -------
    `supportedModules`: dict with all supported modules
    """

    supportedModules: dict[str, ModuleData] = dict()

    # HTTPS
    modData: ModuleData = ModuleData(
        alias="https",
        moduleNames=["https", "https-simple-new"],
        fingerprintFieldPath="ssl.cert.fingerprint.sha256",
        domainFieldPath="ssl.cert.subject.CN",  # One domain per fingerprint
    )

    supportedModules[modData.alias] = modData
    # END HTTPS

    # SSH
    modData: ModuleData = ModuleData(
        alias="ssh",
        moduleNames=["ssh"],
        fingerprintFieldPath="ssh.fingerprint",
        domainFieldPath="domains",  # Multiple domains per fingerprint
        extractorFn=extractDomainFromSSH,
    )

    supportedModules[modData.alias] = modData
    # END SSH

    return supportedModules


def getNestedFieldData(
    scan: dict[str, Any],
    field: FieldPath,
    extractor: Optional[Callable[[str], str]] = None,
) -> str | None:
    """
    Get data from a scan given the desired field, regardless of how nested it is.

    If a extractor function is needed, it is up to the user to implement a viable method under `initSupportedModules()`

    Parameters
    ----------
    `scan`: scan to get data from
    `field`: nested field with data
    `extractor`: extractor function to extract/parse/process the data before returning (optional)

    Returns
    -------
    `data`: data after it has been processed by an extractor function or raw
    """

    data = scan

    # Iteratively traverse parent -> child to get desired field
    for key in field:
        data = data.get(key)

        if data == None:
            return None

    if extractor:
        return extractor(data)

    return data


def extractDataFromFile(
    filepath: str, moduleData: ModuleData
) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, IpTimeSeries], int]:
    """
    Extract data from a Shodan scan file, given a target module.
    The file can be either a .json or .json.bz2 file.

    Parameters
    ----------
    `filepath`: path to the file. Be careful when using relative paths.
    `moduleData`: module

    Returns
    -------
    A tuple containing the following data, in order:
    `fingerprintsPerIp`: a dict of unique fingerprints found per IP address
    `ipsPerFingerprint`: a dict of unique IP addresses found per fingerprint
    `ipFingerprintsOverTime`: a dict of a timeseries for each IP address
    `bannersFound`: total amount of Shodan banners (for this module) found in the file, even if not valid
    """

    # Init data dicts
    fingerprintsPerIp: dict[str, set[str]] = defaultdict(set)
    ipsPerFingerprint: dict[str, set[str]] = defaultdict(set)
    ipFingerprintsOverTime: dict[str, IpTimeSeries] = defaultdict(list)
    bannersFound: int = 0

    logging.info(f"Loading scans from {filepath}")

    # Change extraction method based on whether or not file is compressed
    isFileCompressed: bool = filepath.endswith(".json.bz2")

    if isFileCompressed:
        data = bz2.open(filepath, "rt")
    else:
        data = json.load(open(filepath, "rb"))

    for scan in data:
        # Compressed scans are not dict-ready, so we need to load them
        if isFileCompressed:
            scan: dict[Any, Any] = json.loads(scan)

        try:
            ip: str = scan["ip_str"]
            port: int = scan["port"]
            modName: str = scan["_shodan"]["module"]

            # Count banners found for this module, even if other fields are missing
            if modName in moduleData.moduleNames:
                bannersFound += 1

            timestamp: dt.datetime = dt.datetime.fromisoformat(scan["timestamp"])
            domain: str | None = getNestedFieldData(scan, moduleData.domainField)

            if domain is None:
                continue
        except KeyError:
            # We need every field to perform our analysis, so we skip the scan if they are not available
            # This happens very often, so we won't log it directly
            continue

        # Skip non-desired modules
        if modName not in moduleData.moduleNames:
            continue

        # Get fingerprint for this module
        fingerprint: str | None = getNestedFieldData(
            scan, moduleData.fingerprintField, moduleData.fingerprintExtractor
        )

        # Skip if fingerprint is not available
        if fingerprint == None:
            continue

        # Save data for this scan
        ipsPerFingerprint[fingerprint].add(ip)

        fingerprintsPerIp[ip].add(fingerprint)

        ipFingerprintsOverTime[ip].append((timestamp, fingerprint, port, domain))

    return (fingerprintsPerIp, ipsPerFingerprint, ipFingerprintsOverTime, bannersFound)


def getFingerprintsAndIps(
    args: argparse.Namespace, supportedModules: dict[str, ModuleData]
) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, IpTimeSeries]]:
    """
    Analyzes a collection of shodan scans and finds/builds:

    All unique fingerprints associated with an IP address, for every IP address.

    All unique IP addresses associated with a fingerprint, for every fingerprint.

    A time series describing the fingerprints over time, for every IP address.

    Attention
    ---------
    This function is computationally expensive and may take a while to complete.
    It will also use (almost) all available CPU cores to speed up the process.

    Parameters
    ----------
    `args`: command line arguments
    `supportedModules`: dict of supported modules data

    Returns
    -------
    A tuple in the following order:
    `fingerprintsPerIp`: a dict of unique fingerprints found per IP address
    `ipsPerFingerprint`: a dict of unique IP addresses found per fingerprint
    `ipFingerprintsOverTime`: a dict of a timeseries for each IP address
    """

    # Init final data dicts
    fingerprintsPerIp: dict[str, set[str]] = defaultdict(set)
    ipsPerFingerprint: dict[str, set[str]] = defaultdict(set)
    ipFingerprintsOverTime: dict[str, IpTimeSeries] = defaultdict(list)
    totalBanners: int = 0

    # Get target module data
    moduleData: ModuleData = supportedModules[args.targetModule]

    # Get target files
    scanFiles: list[str] = list()

    for file in os.scandir(args.shodanDir):
        # Skip dirs and non-json files
        if not file.is_file() or not file.path.endswith((".json", ".json.bz2")):
            continue

        scanFiles.append(file.path)

    # Check if any file was found at all
    if len(scanFiles) == 0:
        logging.error(
            f"No compatible files found in directory '{args.shodanDir}'. Please ensure that scans are .json or .json.bz2 files and are formatted correctly"
        )
        exit(3)

    # Prepare to multiprocess data
    partialResults: list[
        tuple[dict[str, set[str]], dict[str, set[str]], dict[str, IpTimeSeries], int]
    ]

    # Leave two cores free, use the rest
    with multiprocessing.Pool(multiprocessing.cpu_count() - 2) as pool:
        partialResults = pool.starmap(
            extractDataFromFile, zip(scanFiles, repeat(moduleData))
        )

    logging.info(f"Aggregating {len(partialResults)} file scan results")

    # Aggregate results
    for (
        partialFingerprintsPerIp,
        partialIpsPerFingerprint,
        partialIpFingerprintsOverTime,
        bannersFound,
    ) in partialResults:
        for ip, fingerprints in partialFingerprintsPerIp.items():
            fingerprintsPerIp[ip] = fingerprintsPerIp[ip].union(fingerprints)

        for fingerprint, ips in partialIpsPerFingerprint.items():
            ipsPerFingerprint[fingerprint] = ipsPerFingerprint[fingerprint].union(ips)

        for ip, timeseries in partialIpFingerprintsOverTime.items():
            ipFingerprintsOverTime[ip].extend(timeseries)

        totalBanners += bannersFound

    logging.info(f"Total {args.targetModule} banners found: {totalBanners}")

    # Sort time series, saving us some time later
    for ip in ipFingerprintsOverTime.keys():
        ipFingerprintsOverTime[ip] = sorted(
            ipFingerprintsOverTime[ip], key=lambda x: x[0]
        )

    logging.info(f"File scan data extraction complete")

    return (fingerprintsPerIp, ipsPerFingerprint, ipFingerprintsOverTime)


def extractShodanData(
    args: argparse.Namespace, supportedModules: dict[str, ModuleData]
) -> None:
    """
    Performs a full Shodan scan data extraction for a given target module.

    Parameters
    ----------
    `args`: command line arguments
    `supportedModules`: dict of supported modules data
    """

    # Default names
    filenameFPI: str = f"{args.cacheFolder}/FPI.pickle"
    filenameIPF: str = f"{args.cacheFolder}/IPF.pickle"
    filenameIFOT: str = f"{args.cacheFolder}/IFOT.pickle"

    logging.info("Starting full Shodan scan data extraction")

    (
        fingerprintsPerIp,
        ipsPerFingerprint,
        ipFingerprintsOverTime,
    ) = getFingerprintsAndIps(args, supportedModules)

    logging.info("Saving results")

    if not os.path.exists(args.cacheFolder):
        os.mkdir(args.cacheFolder)

    pickle.dump(fingerprintsPerIp, open(filenameFPI, "wb"))
    pickle.dump(ipsPerFingerprint, open(filenameIPF, "wb"))
    pickle.dump(ipFingerprintsOverTime, open(filenameIFOT, "wb"))

    logging.info(
        f"Shodan input data has been saved to {args.cacheFolder}. You can now run DynMap with this data."
    )


# Start here
if __name__ == "__main__":
    # Init supported modules
    supportedModules: dict[str, ModuleData] = initSupportedModules()

    # Get args
    parser = initParser(supportedModules)
    args = parser.parse_args()

    # Auto enable log file if log level is DEBUG
    if args.loglevel == "DEBUG" and args.logfile == None:
        args.logfile = f"preprocess_shodan_debug.log"
        print(
            f"A log file is required for log level DEBUG. Logs will be written to '{args.logfile}'"
        )

    # Set up log
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s: %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S %p",
        level=getattr(logging, args.loglevel),
        filename=args.logfile,
        encoding="utf-8",
    )

    # Start execution
    extractShodanData(args, supportedModules)
