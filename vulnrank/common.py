import json
import logging
import pickle
import re
import time
from datetime import datetime
from pathlib import Path
import warnings

import numpy as np
import pandas
import psycopg2
from deltalake import DeltaTable
from pandas import DataFrame

import config


def read_pickle_dict(fp: Path, columns: list[str]) -> pandas.DataFrame:
    with open(fp, "rb") as fd:
        data = pickle.load(fd)
    df = pandas.DataFrame.from_dict(data, orient="index")
    df.reset_index(inplace=True)
    df.columns = columns
    return df


def psql_read_table(
    table: str,
    dbhost: str,
    dbname: str,
    dbuser: str,
    dbpass: str,
    dbport: int = 5432,
) -> pandas.DataFrame:
    connection = psycopg2.connect(
        host=dbhost,
        database=dbname,
        user=dbuser,
        password=dbpass,
        port=dbport,
    )
    cursor = connection.cursor()
    query = f"SELECT * FROM {table};"
    df = pandas.read_sql(query, connection)
    logging.info("Read table %s from PostgreSQL, %d rows", table, len(df))
    cursor.close()
    connection.close()
    return df


def read_kev_json(fp: Path) -> pandas.DataFrame:
    with open(fp, encoding="utf8") as fd:
        data = json.load(fd)
    return pandas.DataFrame(data["vulnerabilities"])


def replace_json_normalize(df: DataFrame, column: str, prefix: str = "") -> DataFrame:
    normalized_df = pandas.json_normalize(df[column])
    colnames = [f"{prefix}{c.replace(' ', '_')}" for c in normalized_df.columns]
    normalized_df.columns = colnames
    return pandas.concat([df.drop(columns=[column]), normalized_df], axis=1)


class DatasetManager:
    def __init__(self, tlhop_epss_report_fp: Path):
        self.tlhop_epss_report_fp: Path = tlhop_epss_report_fp
        assert self.tlhop_epss_report_fp.exists()
        self.table = DeltaTable(self.tlhop_epss_report_fp)
        self.datestr2version: dict[str, int] = {}
        self.datestr2df: dict[str, DataFrame] = {}
        self.kev_df: DataFrame = None
        self.org_df: DataFrame = None
        self.cve_df: DataFrame = None
        self.votes_df: DataFrame = None
        self.device_categories = None
        self.devicetype_categories = None

    def load_datasets(self, datestr_list: list[str]):
        self.build_datestr2version()
        self.load_shodan_df(datestr_list)
        self.load_org_classifications()
        self.load_cve_classifications()
        self.load_kev_database()
        self.load_votes()
        self.kev_set = set(self.kev_df["cveID"].values)

    def build_datestr2version(self):
        shodan_fn_regex = re.compile(r"BR\.(?P<date>\d+)\.json\.bz2")
        write_commits = 0
        last_vacuum_tstamp = None

        # iterate over commits in reverse cronological order:
        for commit in self.table.history():
            # commit timestamp is in milisseconds:
            commit_tstamp = datetime.fromtimestamp(commit["timestamp"] / 1e3)
            operation = commit.get("operation", "")

            if operation == "VACUUM END" and last_vacuum_tstamp is None:
                last_vacuum_tstamp = commit_tstamp - config.RETENTION_VACUUM_TIMEDELTA

            elif operation == "WRITE":
                write_commits += 1

                if last_vacuum_tstamp is not None and commit_tstamp <= last_vacuum_tstamp:
                    message = "Commit version %s too old, ignoring [date=%s]"
                    logging.debug(message, commit["version"], str(commit_tstamp))

                if "userMetadata" in commit:
                    match = shodan_fn_regex.search(commit["userMetadata"])
                    assert match is not None
                    datestr = match.group("date")
                    datestr = time.strftime("%Y-%m-%d", time.strptime(datestr, "%Y%m%d"))
                else:
                    datestr = commit_tstamp.strftime("%Y-%m-%d")

                if datestr in self.datestr2version:
                    logging.warning("Overwriting commit on %s", datestr)
                self.datestr2version[datestr] = commit["version"]

        logging.info(
            "Selected %d of %d commits, start=%s end=%s",
            len(self.datestr2version),
            write_commits,
            min(self.datestr2version.keys()),
            max(self.datestr2version.keys()),
        )

    def load_shodan_df(self, datestr_list: list[str]):
        for datestr in datestr_list:
            version = self.datestr2version[datestr]
            df = DeltaTable(self.tlhop_epss_report_fp, version=version).to_pandas()
            self.datestr2df[datestr] = df

        devices = pandas.Series(
            pandas.unique(pandas.concat([df["device"].dropna() for df in self.datestr2df.values()]))
        )
        self.device_categories = pandas.CategoricalDtype(categories=devices, ordered=True)

        devtypes = pandas.Series(
            pandas.unique(
                pandas.concat([df["devicetype"].dropna() for df in self.datestr2df.values()])
            )
        )
        self.devicetype_categories = pandas.CategoricalDtype(categories=devtypes, ordered=True)

        for df in self.datestr2df.values():
            df["port"] = df["port"].astype("category")
            df["device"] = df["device"].astype(self.device_categories)
            df["devicetype"] = df["devicetype"].astype(self.devicetype_categories)

    def load_kev_database(self):
        self.kev_df = read_kev_json(config.INPUT_KEV_JSON)
        logging.info("KEV database has %d CVEs", len(self.kev_df))

    def load_org_classifications(self):
        self.org_df = read_pickle_dict(config.INPUT_ORG_CLASS_PKL, config.INPUT_ORG_COLS)
        self.org_df = replace_json_normalize(self.org_df, "classification", prefix="org_c_")
        logging.info("Loaded classifications for %d orgs", len(self.org_df))

    def load_cve_classifications(self):
        self.cve_df = read_pickle_dict(config.INPUT_CVE_CLASS_PKL, config.INPUT_CVE_COLS)
        self.cve_df = replace_json_normalize(self.cve_df, "classification", prefix="cve_c_")
        logging.info("Loaded classifications for %d CVEs", len(self.cve_df))

    def load_votes(self):
        users_df = psql_read_table(
            "users",
            config.PSQL_HOST,
            config.PSQL_DB,
            config.PSQL_USER,
            config.PSQL_PASS,
            config.PSQL_PORT,
        )
        votes_df = psql_read_table(
            "votes",
            config.PSQL_HOST,
            config.PSQL_DB,
            config.PSQL_USER,
            config.PSQL_PASS,
            config.PSQL_PORT,
        )
        users_df = users_df.rename(columns={"id": "user_id"})
        users_sum_df = users_df[["user_id", "username"]]
        self.votes_df = pandas.merge(votes_df, users_sum_df, on="user_id", how="left")
        self.votes_df["datestr"] = self.votes_df["vote_date"].astype(str).str[:10]
        logging.info("Loaded %d votes from %d users", len(self.votes_df), len(users_df))

    def sample_data(self, datestr: str, count: int, random_state: int) -> DataFrame:
        assert time.strptime(datestr, "%Y-%m-%d")
        version = self.datestr2version[datestr]
        assert version >= 0
        shodan_df = DeltaTable(self.tlhop_epss_report_fp, version=version).to_pandas()
        shodan_df.dropna(subset=["vulns"], inplace=True)
        logging.info(
            "Loaded %d records from %s in %s", len(shodan_df), datestr, self.tlhop_epss_report_fp
        )

        shodan_df["max_epss"] = shodan_df["vulns_scores"].apply(
            lambda row: max(row.get("epss", [0]))
        )
        shodan_df["max_cvss"] = shodan_df["vulns_scores"].apply(
            lambda row: max(row.get("cvss_score", [0]))
        )

        sampled_df = shodan_df.sample(n=count, random_state=random_state)
        logging.info("Sampled %d entries from %s in %s", count, datestr, self.tlhop_epss_report_fp)
        return sampled_df

    def join_votes_shodan_df(self, df: DataFrame, datestr: str):
        assert time.strptime(datestr, "%Y-%m-%d")
        day_df = self.datestr2df[datestr].copy()
        day_df.set_index("meta_id", inplace=True)

        for column in config.SHODAN_DESIRED_COLUMNS:
            if column not in df.columns:
                df[column] = None
                df[column] = df[column].astype(day_df[column].dtype)

        df.set_index("meta_id", inplace=True)
        df.update(day_df)
        df.reset_index(inplace=True)
        df.dropna(subset=["vulns"], inplace=True)
        df.drop(df[df["username"] == "admin"].index, inplace=True)
        logging.info("Merged Shodan columns")

    def join_org_features(self, features_df: DataFrame, shodan_df: DataFrame):
        df = shodan_df.copy()

        org_cols = [col for col in self.org_df.columns if col.startswith("org_c")]
        for column in org_cols:
            if column not in df.columns:
                df[column] = None
                df[column] = df[column].astype(self.org_df[column].dtype)

        warnings.filterwarnings("ignore", category=pandas.errors.PerformanceWarning)

        # First we should try to join by the _shodan.id field and then join from most specific to least specific
        for index in [["ip_str", "port", "orgname"], ["ip_str", "orgname"], ["orgname"]]:
            org_df = self.org_df.copy()
            org_df.set_index(index, inplace=True)
            org_df = org_df[~org_df.index.duplicated(keep="first")]

            df.rename(columns={"org": "orgname"}, inplace=True)
            df.set_index(index, inplace=True)
            df.update(org_df, overwrite=False)
            df.reset_index(inplace=True)
            df.rename(columns={"orgname": "org"}, inplace=True)

            df.rename(columns={"org_clean": "orgname"}, inplace=True)
            df.set_index(index, inplace=True)
            df.update(org_df, overwrite=False)
            df.reset_index(inplace=True)
            df.rename(columns={"orgname": "org_clean"}, inplace=True)

        warnings.resetwarnings()

        for col in df.columns:
            if col.startswith("org_c_"):
                features_df[col] = df[col]

        logging.info("Merged organization features")

    def join_cve_features(self, df: DataFrame):
        cve_cols = [col for col in self.cve_df.columns if col.startswith("cve_c")]
        for column in cve_cols:
            if column not in df.columns:
                df[column] = None
                df[column] = df[column].astype(self.cve_df[column].dtype)
        self.cve_df.set_index("cve", inplace=True)
        df.set_index("max_epss_cve_id", inplace=True)
        df.update(self.cve_df)
        df.reset_index(inplace=True)
        logging.info("Joined CVE columns")
        self.cve_df.reset_index(inplace=True)

    def build_features_df(self, df: DataFrame, votes: bool = True) -> DataFrame:
        vote_columns = ["username", "vote"]
        copy_columns = ["port", "device", "devicetype"]
        if votes:
            features_df = DataFrame(df[vote_columns + copy_columns])
        else:
            features_df = DataFrame(df[copy_columns])

        def max_epss_cve_id(vulns):
            return max(vulns, key=lambda x: x["epss"])["cve_id"]
        
        def isin_kev(vulns) -> DataFrame:
            return any(vuln["cve_id"] in self.kev_set for vuln in vulns)

        features_df["max_epss_cve_id"] = df["vulns"].apply(max_epss_cve_id)
        features_df["in_kev"] = df["vulns"].apply(isin_kev)
        self.join_cve_features(features_df)

        def summarize_vulns(row):
            vulns = row["vulns"]
            assert isinstance(vulns, np.ndarray)
            vulns = np.atleast_1d(vulns)
            num_vulns = vulns.size
            num_critical = sum(1 for vuln in vulns if vuln["cvss_rank"] == "critical")
            num_high = sum(1 for vuln in vulns if vuln["cvss_rank"] == "high")
            return [num_vulns, num_critical, num_high]

        features_df[["num_vulns", "num_crit_sev", "num_high_sev"]] = df.apply(
            summarize_vulns, axis=1, result_type="expand"
        )

        def summarize_scores(row):
            scores = row["vulns_scores"]
            assert isinstance(scores, dict)
            max_epss = scores["epss"].max()
            max_cvss = scores["cvss_score"].max()
            return [max_epss, max_cvss]

        features_df[["max_epss", "max_cvss"]] = df.apply(
            summarize_scores, axis=1, result_type="expand"
        )

        features_df["num_hostnames"] = df["hostnames"].apply(
            lambda hosts: hosts.size if isinstance(hosts, np.ndarray) else 0
        )
        features_df["num_domains"] = df["domains"].apply(
            lambda domains: domains.size if isinstance(domains, np.ndarray) else 0
        )

        def count_cpes(cpe23s):
            num_cpes = 0
            if cpe23s is not None and isinstance(cpe23s, np.ndarray):
                cpe23s = np.atleast_1d(cpe23s)
                num_cpes = cpe23s.size
            return num_cpes

        features_df["num_cpes"] = df["cpe23"].apply(count_cpes)

        for feat in config.CATEGORICAL_FEATURES:
            assert features_df[feat].dtype == "category", str(features_df[feat].dtype)

        self.join_org_features(features_df, df)
        features_df.drop(columns=["max_epss_cve_id"], inplace=True)

        return features_df
