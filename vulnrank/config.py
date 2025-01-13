import datetime
import os
from pathlib import Path

BASEPATH = Path("/home/pep/30/tlhop-epss-app")
SHODAN_PATH = BASEPATH / "input_data"
OUTPUT_PATH = BASEPATH / "output_data"
TLHOP_EPSS_REPORT_PATH = OUTPUT_PATH / "tlhop-epss-dashboard.delta"

INPUT_KEV_JSON = BASEPATH / "cisa-kev-db.json"
INPUT_CVE_CLASS_PKL = BASEPATH / "org_c/cve_classification/cvesResult.pkl"
INPUT_CVE_COLS = ["cve", "description", "classification"]
INPUT_ORG_CLASS_PKL = BASEPATH / "org_c/v3/orgsResult_v2.pkl"
INPUT_ORG_COLS = ["uuid", "ip_str", "port", "org", "orgname", "classification"]

PSQL_HOST = "127.0.0.1"
PSQL_DB = "postgres"
PSQL_USER = "postgres"
PSQL_PASS = "w!xK3b<js9#Ud6cEe9BjjpJuJC&8"
PSQL_PORT = 5432

RANDOM_STATE = 42

CRON_EXPRESSION = os.environ.get("CRON_EXPRESSION", "*/1 * * * *")
RETENTION_VACUUM_HOURS = 24 * 7
RETENTION_VACUUM_TIMEDELTA = datetime.timedelta(hours=RETENTION_VACUUM_HOURS)

SHODAN_DESIRED_COLUMNS = [
    "timestamp",
    "ip_str",
    "org",
    "org_clean",
    "isp",
    "data",
    "port",
    "hostnames",
    "domains",
    "city",
    "region_code",
    "latitude",
    "longitude",
    "os",
    "device",
    "devicetype",
    "cpe23",
    "http",
    "vulns",
    "vulns_scores",
]
CATEGORICAL_FEATURES = ["port", "device", "devicetype"]
