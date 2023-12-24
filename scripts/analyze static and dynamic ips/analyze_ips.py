# Needed for analysis
import os
import json
import datetime as dt

# Code quality
import pickle
import logging
import argparse

# Code consistency
from typing import Any, NewType
from pydantic import BaseModel, ValidationError

# Expected data format from Shodan .json files
class ShodanData(BaseModel):
    expected: list[dict[str, Any]]

# IP address time series used for Rule 3
IpTimeSeries = NewType('IpTimeSeries', list[tuple[dt.datetime, str, int]])

# Configurable module data for Shodan
class ModuleData:
    def __init__(self):
        self.moduleNames: set[str]       = set()
        self.fingerprintField: list[str] = list()
        self.fingerprintExtractor        = lambda x: x

    def addModuleName(self, mod: str):
        self.moduleNames.add(mod)

    def setFingerprintField(self, field: str):
        self.fingerprintField = field.split(sep='.')

    def setFingerprintExtractor(self, extractorFn):
        self.fingerprintExtractor = extractorFn 

def initSupportedModules() -> dict[str, ModuleData]:
    '''
    Initializes a dictionary containing the ``ModuleData`` for all supported modules.

    All modules must have:

    ``alias``:                 used for argument parsing (so user can select a module)

    ``module names``:          used to filter modules from shodan (multiple names are supported)

    ``fingerprint field``:     used to select a fingerprint from the respective modules (nested fields separated by .)

    ``fingerprint extractor:`` function used to parse/extract the fingerprint from the selected field

    It is up to the user to add support for modules, please refer to the ``https`` and ``ssh`` implementations for guidance

    Returns
    -------
    ``supportedModules``: dict with all supported modules
    '''

    supportedModules: dict[str, ModuleData] = dict()
    
    # HTTPS
    alias: str = 'https'

    modData: ModuleData = ModuleData()

    modData.addModuleName('https')
    modData.addModuleName('https-simple-new')
    modData.setFingerprintField('ssl.cert.fingerprint.sha256')

    supportedModules[alias] = modData
    # END HTTPS

    # SSH
    alias: str = 'ssh'

    modData: ModuleData = ModuleData()

    modData.addModuleName('ssh')
    modData.setFingerprintField('ssh.fingerprint')

    supportedModules[alias] = modData
    # END SSH

    return supportedModules

def getNestedFieldData(scan: dict, modData: ModuleData) -> str | None:
    '''
    Gets fingerprint data from a scan given the desired module, regardless of how nested it is.

    If a fingerprint extractor is needed, it is up to the user to implement a viable method under ``initSupportedModules()``

    Parameters
    ----------
    ``args``: scan to get data from
    ``modData``: module data with a fingerprint field and a fingerprint extractor (optional)

    Returns
    -------
    ``data``: fingerprint data after it has been processed by fingerprintExtractor (if any)
    '''

    data = scan

    # Iteratively traverse parent -> child to get desired field
    for key in modData.fingerprintField:
        data = data.get(key)

        if data is None: break

    return modData.fingerprintExtractor(data)

def initParser(supportedModules: dict[str, ModuleData]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Analyzes IP addresses from a collection of Shodan scans \
                                                  to find static and dynamic IP addresses. The analysis is limited \
                                                  to a Shodan module.')
    
    parser.add_argument('shodanDir', metavar='shodan-dir', type=str,
                        help='directory with a collection of Shodan daily scans (each as a .json file)')
    
    parser.add_argument('targetModule', metavar='target-module', type=str,
                        choices=supportedModules.keys(),
                        help=f"Shodan module to be analyzed. Available options: {', '.join(supportedModules.keys())}")
    
    parser.add_argument('-f', '--logfile', dest='logfile', action='store',
                        default=None,
                        help='file to store log outputs. If not specified, logs will be printed on screen')
    
    parser.add_argument('-l', '--loglevel', dest='loglevel', metavar='LOGLEVEL', action='store',
                        choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'],
                        default='INFO',
                        help='log level. Available options: DEBUG, INFO, WARN, ERROR, FATAL (default: INFO)')

    parser.add_argument('-s', '--save-ips', dest='shouldSaveIps', action='store_true',
                        default=False,
                        help='saves dynamic/static IP addresses found as a .pickle file (default: off)')

    return parser

def getFingerprintsAndIps(
        args: argparse.Namespace, 
        supportedModules: dict[str, ModuleData]
    ) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, IpTimeSeries]]:
    '''
    Analyzes a collection of shodan scans and finds/builds:

    All unique fingerprints associated with an IP address, for every IP address.

    All unique IP addresses associated with a fingerprint, for every fingerprint.

    A time series describing the fingerprints over time, for every IP address.

    Parameters
    ----------
    ``args``: command line arguments
    ``supportedModules``: dict of supported modules data

    Returns
    -------
    A tuple in the following order:
    ``fingerprintsPerIp``: a dict of unique fingerprints found per IP address
    ``ipsPerFingerprint``: a dict of unique IP addresses found per fingerprint
    ``ipFingerprintsOverTime``: a dict of a timeseries for each IP address
    '''
    
    # Init data dicts
    fingerprintsPerIp: dict[str, set[str]]          = dict()
    ipsPerFingerprint: dict[str, set[str]]          = dict()
    ipFingerprintsOverTime: dict[str, IpTimeSeries] = dict()

    # Get target module data
    moduleData: ModuleData = supportedModules[args.targetModule]

    for file in os.scandir(args.shodanDir):
        # Skip dirs and non-json files
        if (not file.is_file() or not file.path.endswith(".json")):
            continue
        
        logging.info(f"Loading scans from {file.name}")

        data: list[dict[str, Any]] = json.load(open(file.path, 'rb'))

        # Validate data
        try:
            ShodanData(expected=data)
        except ValidationError:
            logging.error(f"Data from file {file.name} doesn't match the expected structure: list[dict[str, Any]]. Aborted")
            exit(1)

        for scan in data:
            ip: str      = scan.get('ip_str')
            port: int    = scan.get('port')
            modName: str = scan.get('_shodan').get('module')

            timestamp: dt.datetime = dt.datetime.fromisoformat(scan.get('timestamp'))

            # Skip non-desired modules
            if modName not in moduleData.moduleNames:
                continue

            # Get fingerprint for this module
            fingerprint = getNestedFieldData(scan, moduleData)

            # Skip if fingerprint is not available
            if fingerprint == None:
                continue

            # Add key to dicts if not present
            if fingerprint not in ipsPerFingerprint:
                ipsPerFingerprint[fingerprint] = set()

            if ip not in fingerprintsPerIp:
                fingerprintsPerIp[ip] = set()

            if ip not in ipFingerprintsOverTime:
                ipFingerprintsOverTime[ip] = list()

            # Save data for this scan
            ipsPerFingerprint[fingerprint].add(ip)

            fingerprintsPerIp[ip].add(fingerprint)

            ipFingerprintsOverTime[ip].append((timestamp, fingerprint, port))

    # Check if any data was found at all
    if (len(fingerprintsPerIp) == 0 and len(ipsPerFingerprint) == 0):
        logging.error(f"No compatible files found in directory '{args.shodanDir}'. Please ensure that scans are .json files")
        exit(2)
    
    return fingerprintsPerIp, ipsPerFingerprint, ipFingerprintsOverTime

def findStaticAndDynamicIps(
        fingerprintsPerIp: dict[str, set[str]], 
        ipsPerFingerprint: dict[str, set[str]],
        ipFingerprintsOverTime: dict[str, IpTimeSeries]
    ) -> tuple[set[str], set[str]]:
    '''
    Analyzes a collection of IP addresses and applies a set of rules searching for dynamic IP addresses.

    Every discarded IP address is flagged as static.
    
    If the log level is set to ``DEBUG``, a trace of every rule applied will be logged.

    Parameters
    ----------
    ``fingerprintsPerIp``: a dict of unique fingerprints found per IP address
    ``ipsPerFingerprint``: a dict of unique IP addresses found per fingerprint
    ``ipFingerprintsOverTime``: a dict of a timeseries for each IP address

    Returns
    -------
    A tuple in the following order:
    ``staticIps``: a set of all static IP addresses found
    ``dynamicIps``: a set of all dynamic IP addresses found
    '''
    
    # Initial dicts
    staticIps: set[str]          = set()
    dynamicIps: set[str]         = set()

    possibleDynamicIps: set[str] = set()

    # Rules 1 and 2
    for ip, fingerprints in fingerprintsPerIp.items():
        # Rule 1: This IP address must have more than one fingerprint
        if len(fingerprints) == 1:
            logging.debug(f"Rule 1 - IP address {ip} flagged as static")

            staticIps.add(ip)
            continue
        
        # Rule 2: If this IP address has two or more fingerprints, all of them must be seen
        # across two or more IP addresses
        static = False

        for fp in fingerprints:
            # If this fingerprint has been assigned to just this IP address, this IP address is likely static
            if len(ipsPerFingerprint[fp]) == 1:
                logging.debug(f"Rule 2 - IP address {ip} flagged as static")

                staticIps.add(ip)
                static = True
                break
        
        # Save for processing in Rule 3
        if not static:
            logging.debug(f"Rule 2 - IP address {ip} flagged as possible dynamic")
            possibleDynamicIps.add(ip)

    # Rule 3: Given a timeseries for every possible dynamic IP address. For every scanned port of those IP addresses, 
    # analyze if the fingerprints have the pattern abbaaacbbaa instead of aaaaabbbbcccc. 
    
    for ip in possibleDynamicIps:
        timeSeries: list[tuple[dt.datetime, str, int]] = sorted(ipFingerprintsOverTime[ip], key=lambda x: x[0])

        # Static by default
        allPortsHaveStaticPattern = True

        # Track current fingerprint seen for a given port, used to detect when fingerprint changes
        currentFingerprintSeenByPort: dict[int, str] = dict()

        # Track fingerprint progression for a given port
        seenFingerprintsPerPort: dict[int, set[str]] = dict()

        logging.debug(f"Rule 3 - Time series for IP address {ip}")
    
        for timestamp, fingerprint, port in timeSeries:
            logging.debug(f"Rule 3 - T: {timestamp} P: {port} F: {fingerprint}")

            # New port
            if port not in seenFingerprintsPerPort:
                # Currently scanning this fingerprint
                currentFingerprintSeenByPort[port] = fingerprint

                # Empty seen for now
                seenFingerprintsPerPort[port] = set()

            # Seen port
            # If fingerprint is different from currently scanned, we might have a new fingerprint
            if fingerprint != currentFingerprintSeenByPort[port]:
                if fingerprint in seenFingerprintsPerPort[port]:
                    # Fingerprint is not new and has been seen before, so at least one fingerprint for this port has the pattern BBBAAABB
                    allPortsHaveStaticPattern = False
                    break
                else:
                    # If it hasn't been seen before, a new fingerprint has been found for this port
                    # Save the last fingerprint 
                    seenFingerprintsPerPort[port].add(currentFingerprintSeenByPort[port])

                    # Update current fingerprint being scanned
                    currentFingerprintSeenByPort[port] = fingerprint

        # Result
        if allPortsHaveStaticPattern:
            logging.debug(f"Rule 3 - IP address {ip} flagged as static")
            staticIps.add(ip)
        else:
            logging.debug(f"Rule 3 - IP address {ip} flagged as dynamic")
            dynamicIps.add(ip)

    return staticIps, dynamicIps

# Start here
if __name__ == "__main__":
    # Load supported modules
    supportedModules = initSupportedModules()

    # Get args
    parser = initParser(supportedModules)
    args   = parser.parse_args()

    # Auto enable log file if log level is DEBUG
    if args.loglevel == 'DEBUG' and args.logfile == None:
        print("A log file is required for log level DEBUG. Logs will be written to 'debug.log'")
        args.logfile = 'debug.log'
        
    # Set up log
    logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s', 
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=getattr(logging, args.loglevel),
                        filename=args.logfile,
                        encoding='utf-8')
    
    # Step 1: Get fingerprints per IP address and IP addresses per fingerprint
    logging.info(f'Selected module: {args.targetModule}')

    fingerprintsPerIp, ipsPerFingerprint, ipFingerprintsOverTime = getFingerprintsAndIps(args, supportedModules)

    # Step 2: Apply rules to filter dynamic/static ips
    logging.info('Filtering IP addresses')

    staticIps, dynamicIps = findStaticAndDynamicIps(fingerprintsPerIp, ipsPerFingerprint, ipFingerprintsOverTime)

    # Step 3: Log output and save results to .pickle files
    logging.info(f"Found {len(staticIps)} static IP addresses")
    logging.info(f"Found {len(dynamicIps)} dynamic IP addresses")
    logging.info(f"Static IP addresses ratio {100 * len(staticIps) / (len(dynamicIps) + len(staticIps)):.6f}%")

    if args.shouldSaveIps:
        pickle.dump(staticIps,  open('static_ips.pickle', 'wb'))
        pickle.dump(dynamicIps, open('dynamic_ips.pickle', 'wb'))

        logging.info("Static and Dynamic IP addresses have been written to static_ips.pickle and dynamic_ips.pickle respectively")