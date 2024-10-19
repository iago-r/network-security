import argparse
import bz2
import json
import logging
import os
from argparse import RawTextHelpFormatter
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Optional

import ijson
from pydantic import BaseModel, Field

CPE_FIELD_IN_SHODAN = "cpe23"
IP_FIELD_IN_SHODAN = "ip_str"
PORT_FIELD_IN_SHODAN = "port"
MODULE_FIELD_IN_SHODAN = "module"
PREFIX_MODULE_FIELD_IN_SHODAN = "_shodan"

class FileSummary:
    """
    Class to handle functions to analyze Shodan and Censys data, reading 
    information, organizing the data and then storing the .json file with the 
    results. The defined functions are used in the AnalysisShodanCensysData class 
    in the 'temporal_scan' and 'probe_data' functions.
    """

    def __init__(self):
        self.days_scan: dict[str, dict] = {}
        self.unique_ips: list[int] = [0]
        self.all_ips: list[str] = []
        self.repeated_ip_scan: list[int] = [0]
        self.ip_scaned_again_same_day: list[int] = [0]
        self.ips_scanned: list[int] = [0]
        self.attributes_collected: list[str] = []
        self.scan_modules: dict[str, set[str]] = {}
        self.cpe_by_ip: dict[str, set] = {}

    def add_info_temporal_scan(self, ip: str, timestamp: datetime, index: int):
        date = f"{timestamp.year}:{timestamp.month}:{timestamp.day}"

        self.ips_scanned[index] += 1

        if ip in self.days_scan:

            if date in self.days_scan[ip]["timestamp"]:
                self.ip_scaned_again_same_day[index] += 1
            else:
                self.repeated_ip_scan[index] += 1

            self.days_scan[ip]["timestamp"].add(date)
            self.days_scan[ip]["scans"] += 1
        else:
            self.days_scan[ip] = {"timestamp": set(), "scans": 1}
            self.days_scan[ip]["timestamp"].add(date)

        if ip not in self.all_ips:
            self.all_ips.append(ip)
            self.unique_ips[index] += 1

    def add_info_probe_data(
        self,
        ip: str,
        port: str,
        scan_attributes: str,
        module: str,
        cpe_list: list,
    ):

        if not (scan_attributes) in self.attributes_collected:
            self.attributes_collected.append(scan_attributes)

        if ip not in self.cpe_by_ip:
            self.cpe_by_ip[ip] = set()

        if cpe_list:
            for cpe in cpe_list:
                self.cpe_by_ip[ip].add(cpe)

        if (module) in self.scan_modules:
            self.scan_modules[module].add(port)
        else:
            self.scan_modules[module] = set()
            self.scan_modules[module].add(port)

    def update_info_temporal_scan(self):
        self.ips_scanned.append(0)
        self.unique_ips.append(0)
        self.repeated_ip_scan.append(0)
        self.ip_scaned_again_same_day.append(0)

    def dump_info_temporal_scan(self, output_directory: str, initial_date, final_date):

        # Sort ips by the number of scans
        for ip, data in self.days_scan.items():
            self.days_scan[ip]["timestamp"] = sorted(data["timestamp"])

        sorted_daysScan = sorted(
            self.days_scan.items(), key=lambda x: x[1]["scans"], reverse=True
        )

        # Group data for JSON output
        data = {
            "days_summary": [
                {
                    "Day": i + 1,
                    "IpsScanned": self.ips_scanned[i],
                    "UniqueIps": self.unique_ips[i],
                    "RepeatedIpScan": self.repeated_ip_scan[i],
                    "IpScanedAgainOnTheSameDay": self.ip_scaned_again_same_day[i],
                }
                for i in range(len(self.ips_scanned) - 1)
            ],
            "sorted_daysScan": sorted_daysScan, 
        }

        # Format output file name
        output_path = os.path.join(
            output_directory, f"TemporalScan_from_{initial_date}_to_{final_date}.json"
        )

        with open(output_path, "w") as file:
            json.dump(data, file, indent=6)

    def dump_info_probe_data(self, output_directory: str):

        # store info collected with parentheses
        self.attributes_collected = [
            keysDict for keysDict in self.attributes_collected
        ]

        formated_services_provided = []
        for i in self.attributes_collected:
            formated_services_provided.extend(i)

        formated_services_provided = list(set(formated_services_provided))

        # format data to build json
        modules_shodan_serializable = {
            module: {"ports": list(ports), "count": len(ports)}
            for module, ports in self.scan_modules.items()
        }

        ips_scanned_serializable = {
            ip: {"cpe": list(cpe)} for ip, cpe in self.cpe_by_ip.items()
        }

        data = {
            "modulesShodan": modules_shodan_serializable,
            "uniqueModulesCount": len(self.scan_modules),
            "servicesProvided": formated_services_provided,
            "uniqueIpsCount": len(self.cpe_by_ip),
            "ipsScanned": ips_scanned_serializable,
        }

        # Format output file name
        output_path = os.path.join(output_directory, "modules_and_ports.json")

        with open(output_path, "w") as file:
            json.dump(data, file, indent=4)


class Location(BaseModel):
    city: str
    longitude: float
    latitude: float
    country_code: str
    country_name: str
    continent: str
    province: str


class OperatingSystem(BaseModel):
    vendor: str


class AutonomousSystem(BaseModel):
    name: str
    asn: int
    bgp_prefix: str
    description: str
    country_code: str


class Shodan(BaseModel):
    """class to handle and store Shodan and Censys (parsed to Shodan format) data"""
    ip_str: str
    cpe23: list[str] = []
    location: Optional[Location]
    operating_system: Optional[OperatingSystem]
    autonomous_system: Optional[AutonomousSystem]
    timestamp: Optional[str]
    dns: Optional[dict[str, dict[str, list[str]]]]
    product: str = ""
    org: str = ""
    shodan: dict[str, str] = Field(
        ..., alias=PREFIX_MODULE_FIELD_IN_SHODAN
    )  # _ is private atribute in Pydantic, so alias is used to rename field
    port: int

    @classmethod
    def parse_row(cls, scan: dict):
        cpe = (
            [scan["operating_system"]["cpe"]]
            if ("operating_system" in scan) and ("cpe" in scan["operating_system"])
            else []
        )

        location_data = scan.get("location", {})
        location_data["country_name"] = location_data["country"]
        location_data["longitude"] = scan["location"]["coordinates"]["longitude"]
        location_data["latitude"] = scan["location"]["coordinates"]["latitude"]
        location = Location(**location_data) if location_data else None

        operating_system_data = scan.get("operating_system", {}).get("vendor", "")
        operating_system = (
            OperatingSystem(vendor=operating_system_data)
            if operating_system_data
            else None
        )

        autonomous_system_data = scan.get("autonomous_system", {})
        autonomous_system = (
            AutonomousSystem(**autonomous_system_data)
            if autonomous_system_data
            else None
        )

        # handling the different date formats in Censys
        timestamp_field = scan.get("last_updated_at", "")
        if "." in timestamp_field:
            # Timestamp with fractional seconds
            timestamp = (
                datetime.strptime(timestamp_field, "%Y-%m-%dT%H:%M:%S.%fZ")
                .replace(tzinfo=None)
                .isoformat()
            )
        elif "+" in timestamp_field:
            timestamp = (
                datetime.strptime(timestamp_field, "%Y-%m-%dT%H:%M:%S.%f%z")
                .replace(tzinfo=None)
                .isoformat()
            )
        else:
            # Timestamp without fractional seconds
            timestamp = (
                datetime.strptime(timestamp_field, "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=None)
                .replace(microsecond=1)
                .isoformat()
            )

        dns_data = scan.get("dns", {})
        dns = dns_data if dns_data else {}

        services_data = scan.get("services", {})
        port = services_data.get("port")
        shodan_module = {
            MODULE_FIELD_IN_SHODAN: services_data.get("extended_service_name")
        }

        return Shodan(
            ip_str=scan.get("ip", ""),
            cpe23=cpe,
            location=location,
            operating_system=operating_system,
            autonomous_system=autonomous_system,
            timestamp=timestamp,
            dns=dns,
            product=scan.get("operating_system", {}).get("product", ""),
            org=scan.get("autonomous_system", {}).get("name", ""),
            port=port,
            _shodan=shodan_module,
        )


class AnalysisShodanCensysData:
    """class to load, filter and make analysis in shodan and censys data"""

    def load_censys_in_shodan_format(
        self, input_directory_load_Censys, output_directory_load_Censys
    ):
        """
        load_censys_in_shodan_format: parse censys file (.json.bz2) to shodan format (.json)

        input: directory with initial data and output direcoty to store censys file in shodan format

        return: none. Will be stored censys file in shodan format in the path: .../inputDirectory/censys_formated/
        """

        # Ufmg ips directory
        directory = input_directory_load_Censys

        if not (os.path.exists(directory) and os.path.isdir(directory)):
            logging.warning(f"Invalid directory: {directory}")
            raise Exception("Directory not valid or not exists")

        for file in os.scandir(directory):

            # Skip dirs and non-json files
            if (
                not file.is_file()
                or not file.name.endswith(".json.bz2")
                or not file.name.lower().startswith("censys")
            ):
                logging.warning(f"Invalid file: {file.name}. Skipping ...")
                continue

            logging.info(f"Opening file: {file}")

            info_Censys_to_Shodan_format: list[dict] = []

            # read all scans
            with bz2.open(file, "rt") as f:

                content = f.read()

                scan = json.loads(content)

                for line in scan:

                    for i in line["services"]:
                        line["services"] = i

                        # parse the information using pydantic class
                        info_scanned = Shodan.parse_row(line)

                        info_Censys_to_Shodan_format.append(
                            info_scanned.model_dump(exclude=None, by_alias=True)
                        )
                        info_scanned = {}  # clean the dict

            # create new filename and ignoring extension .json.bz2
            filename_output = (
                file.name.split(".")[0] + ".formated." + file.name.split(".")[1]
            )

            logging.info(f"Creating new folder: {output_directory_load_Censys}")
            os.makedirs(output_directory_load_Censys, exist_ok=True)

            with open(
                f"{output_directory_load_Censys}{filename_output}.json", "w"
            ) as file:
                json.dump(info_Censys_to_Shodan_format, file, indent=6)

    def probe_data_shodan_and_censys(
        self, input_directory_probe_data, output_directory_probe_data
    ):

        """
        probe_data_shodan_and_censys: analyzes data from shodan and censys (in shodan format) gathering information such as amount of IPS, scanning modules...

        input: directory with initial data and output path to store results

        return: none. Will be stored info about scanning modules, analyzed ips and services provided by the scan in the path: .../outputDirectory/modules_and_ports.json"
        """

        # Ufmg ips directory
        if not (
            os.path.exists(input_directory_probe_data)
            and os.path.isdir(input_directory_probe_data)
        ):
            logging.warning(f"Invalid directory: {input_directory_probe_data}.")
            raise Exception("Directory not valid or not exists")

        file_summary = FileSummary()

        for file in os.scandir(input_directory_probe_data):
            # Skip dirs and non-json files
            if not file.is_file() or not file.path.endswith(".json"):
                logging.warning(f"Invalid file: {file.path}. Skipping ...")
                continue

            logging.info(f"Opening file: {file}")

            with open(file.path, "r") as file:
                objects = ijson.items(file, "item")

                # Print the value of the 'name' key directly for each dictionary
                for scan in objects:

                    ip = scan["ip_str"]

                    scan_attributes = scan.keys()

                    cpe = []
                    if "cpe23" in scan:
                        cpe = scan["cpe23"]

                    port = scan["port"]

                    module = scan["_shodan"]["module"]

                    file_summary.add_info_probe_data(
                        ip, port, scan_attributes, module, cpe
                    )

            file_summary.dump_info_probe_data(output_directory_probe_data)

    def temporal_scan_ip_shodan_censys(
        self, input_directory: str, output_directory: str
    ):

        """
        temporal_scan_ip_shodan_censys: temporal analysis in shodan and censys (in shodan format) data

        input: input directory with initial data and output directory to store results

        return: none. Will be stored info about the IPs analyzed throughout the days in the path: .../outputDirectory/TemporalScan_from_{starting date analyzed}_to_{final date analyzed}.json"
        """

        # UFMG ips directory
        if not (os.path.exists(input_directory) and os.path.isdir(input_directory)):
            logging.info(f"The input directory {input_directory} does not exist")
            raise Exception("Directory not valid or does not exist")

        file_summary = FileSummary()

        # Read file names first to order and open files in temporal order
        files = [
            file.name
            for file in os.scandir(input_directory)
            if file.is_file() and file.name.endswith(".json")
        ]
        sorted_files = sorted(files)

        if not sorted_files:
            logging.error(
                f"No valid .json files to do temporal analysis in the directory: {input_directory}"
            )
            raise Exception("No valid files in the input directory")

        # Reading date by the filename
        initial_date = datetime.strptime(
            sorted_files[0].split(".")[-2], "%Y%m%d"
        ).date()
        final_date = datetime.strptime(sorted_files[-1].split(".")[-2], "%Y%m%d").date()

        for file_name in sorted_files:

            logging.info(f"Opening file: {file_name}")

            input_path = os.path.join(input_directory, file_name)

            index = 0
            with open(input_path, "r") as file:
                objects = ijson.items(file, "item")

                # Print the value of the 'name' key directly for each dictionary
                for scan in objects:

                    ip = scan["ip_str"]

                    timestamp = datetime.strptime(
                        scan["timestamp"], "%Y-%m-%dT%H:%M:%S.%f"
                    )

                    file_summary.add_info_temporal_scan(ip, timestamp, index)

            index += 1
            file_summary.update_info_temporal_scan()

        file_summary.dump_info_temporal_scan(output_directory, initial_date, final_date)

    def filter_ufmg_shodan(
        self, input_ip_UFMG, input_directory_filter_UFMG, output_directory_filter_UFMG
    ):
        """
        filter_ufmg_shodan: filter ufmg information in shodan data. The filter consider that the date of the scan is in the filename

        input: ipUFMG to filter the data, the directory with the initial shodan files and the directory where the results will be saved (filtered shodan files)

        return: none. Will be stored the new shodan files in the path: ...inputDirectory/shodan_UFMG/
        """

        # UFMG ips
        json_UFMG = []

        # UFMG subnet
        ip_UFMG = ip_network(
            input_ip_UFMG
        )  # using ip_network to use function subnet_of

        if not (
            os.path.exists(input_directory_filter_UFMG)
            and os.path.isdir(input_directory_filter_UFMG)
        ):
            logging.error(f"Invalid directory: {input_directory_filter_UFMG}.")
            raise Exception("Directory not valid or not exists")

        files = [
            file.name
            for file in os.scandir(input_directory_filter_UFMG)
            if file.is_file()
            and file.name.endswith(".json.bz2")
            and file.name.split(".")[1]
        ]
        sorted_files = sorted(files)

        for file in sorted_files:

            if not file.endswith(".json.bz2") or not file.startswith("BR."):
                logging.warning(f"Invalid file: {file}. Skipping ...")
                continue

            logging.info(f"Opening file: {file}")

            # filename = f"{inputDirectoryFilterUFMG}{file}"
            filename = os.path.join(input_directory_filter_UFMG, file)

            qty = 0

            f = bz2.open(filename, "rt")

            if f == None:
                logging.warning(f"Invalid file: {filename}. Skipping ...")
                f.close()
                continue

            for line in f:
                scan = json.loads(line)

                ip = scan.get(IP_FIELD_IN_SHODAN)

                if ip != None and ip_address(ip) in (ip_UFMG):
                    json_UFMG.append(scan)
                    qty += 1

            logging.info(f"Found {qty} UFMG IPs in file: {file}")

            # Save stuff and format output path
            filename_output = (
                file.split(".")[0] + ".UFMG." + file.split(".")[1]
            )  # ignoring file name extension .json.bz2
            output_path = os.path.join(output_directory_filter_UFMG, filename_output)

            logging.info(f"Creating new folder: {output_directory_filter_UFMG}")
            os.makedirs(output_directory_filter_UFMG, exist_ok=True)

            with open(f"{output_path}.json", "w") as f:
                json.dump(json_UFMG, f, indent=6)

            f.close()


def return_input_parameters():
    parser = argparse.ArgumentParser(
        description="""--> Inform the parameters to run all the following functions listed above:

    * Important: Is considered that the Shodan files respect the following name formats "BR.YYYYMMDD.json.bz2" or "BR.YYYYMMDD.json" and the Censys file "CENSYS-UFMG.YYYYMMDD.json.bz2" or "CENSYS-UFMG.YYYYMMDD.json" where YYYY is the year, MM the month and DD the day.

    * Important: Is considered that Censys data are from UFMG.

    Required parameters:
        outputDirectory = existing directory to store results and intermediate data
    
    Optional parameters:
        --ipUFMG = UFMG ip to filter input data. Used if will be informed Shodan data from Brasil
        --directoryShodan = used if will be informed Shodan data
        --directoryCensys = used if will be informed Censys data
        --directoryStoreCensysShodanFormat = used if will be parsed Censys data do Shodan format
        --directoryStoreUFMGShodanData = used if will be filtered the UFMG data in Shodan files
        
    --> Functions that will be executed:
                                                        
    Filter ufmg shodan: 
        Filter UFMG data in shodan file.
    
    Load censys in shodan format: 
        Used if the input file is from Censys -> will be parsed to shodan format
    
    Probe data shodan and censys: 
        Find information about services, modules, ports and ips in scan from shodan and censys (in shodan format) data.
    
    Temporal scan ip shodan: 
        Make a temporal analysis from shodan and censys (in shodan format) data.
                                     
    """,
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument(
        "--directoryShodan",
        dest="directoryShodan",
        action="store",
        metavar="directory-Shodan",
        type=str,
        help="directory with Shodan data",
        required=False,
    )

    parser.add_argument(
        "--directoryStoreUFMGShodanData",
        dest="directoryStoreUFMGShodanData",
        action="store",
        metavar="directory-StoreUFMGShodanData",
        type=str,
        help="inform the directory name that will be created to store UFMG info filtered from Shodan data",
        required=False,
    )

    parser.add_argument(
        "--directoryCensys",
        dest="directoryCensys",
        action="store",
        metavar="directory-censys",
        type=str,
        help="directory with censys data (will be parsed to shodan format)",
        required=False,
    )

    parser.add_argument(
        "--directoryStoreCensysShodanFormat",
        dest="directoryStoreCensysShodanFormat",
        action="store",
        metavar="directory-StoreCensysShodanFormat",
        type=str,
        help="inform the directory name that will be created to store Censys data in Shodan format",
        required=False,
    )

    parser.add_argument(
        "--ipUFMG",
        dest="ipUFMG",
        action="store",
        metavar="ipUFMG",
        type=str,
        help="UFMG ip to filter input data (required if is passed shodan directory)",
        required=False,
    )

    parser.add_argument(
        "--outputDirectory",
        action="store",
        dest="outputDirectory",
        metavar="outputDirectory",
        required=True,
        type=str,
        help="existing directory to store results and intermediate data",
    )

    args = parser.parse_args()

    return args


def censys_analysis(args, analysis):
    if not args.directoryStoreCensysShodanFormat:
        logging.info(
            "It is necessary to inform the directory to store Censys data in Shodan format"
        )
        raise Exception("Missing directoryStoreCensysShodanFormat parameter")

    # will be created a new directory to store censys data formatted --> the following funcionts will read censys data formatted from this directory
    newFolderCensysInShodanFormat = os.path.join(
        args.directoryCensys, args.directoryStoreCensysShodanFormat
    )

    logging.info("Starting function: load_censys_in_shodan_format in path")
    analysis.load_censys_in_shodan_format(
        args.directoryCensys, newFolderCensysInShodanFormat
    )

    logging.info("Starting function: probe_data_shodan_and_censys")
    analysis.probe_data_shodan_and_censys(
        newFolderCensysInShodanFormat, args.outputDirectory
    )

    logging.info("Starting function: temporal_scan_ip_shodan_censys")
    analysis.temporal_scan_ip_shodan_censys(
        newFolderCensysInShodanFormat, args.outputDirectory
    )


def shodan_analysis(args, analysis):
    if not args.ipUFMG:
        logging.info("It is necessary to inform ipUFMG to analyze the shodan data")
        raise Exception("Missing ipUFMG parameter")

    if not args.directoryStoreUFMGShodanData:
        logging.info(
            "It is necessary to inform the directory to store UFMG data from Shodan"
        )
        raise Exception("Missing directoryStoreCensysShodanFormat parameter")

    # will be created a new directory to store filtered shodan data --> the following functions will read ufmg shodan data formatted from this directory
    newFolderFilteredShodanUFMG = os.path.join(
        args.directoryShodan, args.directoryStoreUFMGShodanData
    )

    logging.info("Starting function: filter_ufmg_shodan")
    analysis.filter_ufmg_shodan(
        args.ipUFMG, args.directoryShodan, newFolderFilteredShodanUFMG
    )

    logging.info("Starting function: probe_data_shodan_and_censys")
    analysis.probe_data_shodan_and_censys(
        newFolderFilteredShodanUFMG, args.outputDirectory
    )

    logging.info("Starting function: temporal_scan_ip_shodan_censys")
    analysis.temporal_scan_ip_shodan_censys(
        newFolderFilteredShodanUFMG, args.outputDirectory
    )


if __name__ == "__main__":

    logging.basicConfig(level=logging.DEBUG)

    args = return_input_parameters()

    if not args.outputDirectory:
        logging.info("It is necessary to inform where to store the results")
        raise Exception("Missing outputDirectory parameter")

    analysis: AnalysisShodanCensysData = AnalysisShodanCensysData()

    if args.directoryCensys:

        censys_analysis(args, analysis)

    if args.directoryShodan:

        shodan_analysis(args, analysis)
