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
    colnames = [f"{prefix}{c.replace(" ", "_")}" for c in normalized_df.columns]
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
        # self.tlhop_epss_views_fp: Path = tlhop_epss_views_fp
        # self.n_views = 3
        # self.sampled_data = None
        # assert self.tlhop_epss_views_fp.exists()

    def load_datasets(self, datestr_list: list[str]):
        self.build_datestr2version()
        self.load_shodan_df(datestr_list)
        self.load_org_classifications()
        self.load_cve_classifications()
        self.load_kev_database()
        self.load_votes()

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

    # def last_write_commit_tstamp(self) -> Optional[datetime]:
    #     for commit in self.table.history():
    #         if commit.get("operation", "") == "WRITE":
    #             return datetime.fromtimestamp(commit["timestamp"] / 1e3)
    #     return None

    # def get_sorted_dates(self) -> list[str]:
    #     return sorted(list(self.datestr2version.keys()), reverse=True)

    # def get_last_write_dump_datestr(self) -> Optional[str]:
    #     if dates := self.get_sorted_dates():
    #         return dates[0]
    #     return None

    # def get_view_dataset(self, datestr: str, code):
    #     if version := self.datestr2version[datestr]:
    #         filepath = self.tlhop_epss_views_fp_template.format(code)
    #         logging.debug("Loading view from %s", filepath)
    #         return DeltaTable(filepath, version=version).to_pandas()
    #     else:
    #         return pd.DataFrame()

    # def get_report_dataset(
    #     self,
    #     datestr: str,
    #     columns: Optional[list[str]] = None,
    #     condition=None,
    # ):
    #     if version := self.datestr2version.get(datestr):
    #         return (
    #             DeltaTable(self.tlhop_epss_report_fp, version=version)
    #             .to_pyarrow_dataset()
    #             .to_table(filter=condition, columns=columns)
    #             .to_pandas()
    #         )
    #     else:
    #         msg = "Tried to access nonexistent commit %s on %s"
    #         logging.warning(msg, datestr, self.tlhop_epss_report_fp)
    #         return pd.DataFrame()

    # def get_report_dataset_new(
    #     self,
    #     day,
    #     columns=None,
    #     condition=None,
    #     single_output=False,
    #     start=0,
    #     finish=-1,
    #     sort_by="score",
    #     ascending=False,
    # ):
    #     commit = self.retrive_commit(day)
    #     df = None
    #     if commit >= 0:
    #         filepath = self.tlhop_epss_report_path

    #         print(f"Reading report of day {day}")
    #         dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()

    #         if single_output:
    #             df = dt.filter(condition).head(1).to_pydict()
    #         else:
    #             table = dt.to_table(filter=condition, columns=None)
    #             df = table.to_pandas()
    #             # df['score'] = df['vulns_scores'].apply(lambda x: x.get('epss', []) if isinstance(x, dict) else [])
    #             # df['score'] = df['score'].apply(lambda probs: 1 - np.prod([1 - p for p in probs]))
    #             df["score"] = df["vulns_scores"].apply(
    #                 lambda x: max(x.get("epss", [0])) if isinstance(x, dict) else 0
    #             )
    #             df = df.drop(columns=["vulns_scores"])
    #             # df = df.sort_values(by=sort_by, ascending=ascending)

    #             # Sample 600 random entries
    #             df = df.sample(n=600, random_state=42)

    #             if finish > 0:
    #                 df = df.iloc[start:finish]

    #         file_path = "file_ips.csv"
    #         df.to_csv(file_path, index=False)
    #         print(f"DataFrame saved to {file_path} successfully.")

    #     return df

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

    # def get_report_each(
    #     self,
    #     day,
    #     user_id=None,
    #     columns=None,
    #     condition=None,
    #     single_output=False,
    #     start=0,
    #     finish=-1,
    #     sort_by="score",
    #     ascending=False,
    # ):
    #     """
    #     Fetch 120 entries for each user from pre-sampled data.
    #     If the data is not yet sampled for the current day, it will sample it first.
    #     """
    #     if self.sampled_data is None:
    #         self.sample_data(day, 777, 600)

    #     if self.sampled_data is not None:
    #         print(f"Using pre-sampled data for day {day} for user {user_id}")
    #         df = self.sampled_data.copy()

    #         if single_output:
    #             df_filtered = df.query(condition) if condition else df
    #             df = df_filtered.head(1).to_dict(orient="records")
    #         else:
    #             if condition:
    #                 df = df.query(condition)

    #             # df = df.sort_values(by=sort_by, ascending=ascending)

    #             num_users = 6
    #             entries_per_user = 120

    #             user_index = user_id % num_users
    #             start_index = user_index * entries_per_user
    #             end_index = start_index + entries_per_user

    #             df = df.iloc[start_index:end_index]

    #             if finish > 0:
    #                 df = df.iloc[start:finish]
    #     else:
    #         df = pd.DataFrame()

    #     return df

    # def get_total_entries_new(self, day, condition=None):
    #     commit = self.retrive_commit(day)
    #     total_entries = 0
    #     if commit >= 0:
    #         filepath = self.tlhop_epss_report_path
    #         dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()
    #         if condition:
    #             total_entries = dt.filter(condition).count_rows()
    #         else:
    #             total_entries = dt.count_rows()
    #     return total_entries

    # def remove_old_data(self):
    #     # default of 1 week
    #     filepaths = [self.tlhop_epss_report_path] + [
    #         self.tlhop_epss_views_path.format(code + 1) for code in range(self.n_views)
    #     ]

    #     for filepath in filepaths:
    #         filepath = filepath.replace("//", "/")
    #         print(
    #             f"[INFO][DatasetManager][remove_old_data] - checking file {filepath}",
    #             flush=True,
    #         )
    #         try:
    #             dt = DeltaTable(filepath)
    #             dt.vacuum(
    #                 retention_hours=RETENTION_VACUUM_HOURS,
    #                 dry_run=False,
    #                 enforce_retention_duration=False,
    #             )
    #         except:
    #             print(
    #                 f"[ERROR][DatasetManager][remove_old_data] - error to vacuum file '{filepath}'",
    #                 flush=True,
    #             )

    # def waiting_next_file(self, mode="latest"):
    #     next_date = self.last_dump_date().replace("-", "")

    #     filepath = SHODAN_FOLDER + "/BR.{pattern}.json.bz2"
    #     available_dates = [
    #         os.path.basename(s)[3:-9]
    #         for s in sorted(glob.glob(filepath.format(pattern="*")))
    #     ]

    #     found_files = [
    #         day[0:4] + "-" + day[4:6] + "-" + day[6:8]
    #         for day in available_dates
    #         if next_date < day
    #     ]
    #     if len(found_files) > 0:
    #         if mode == "all":
    #             print(
    #                 "[INFO][waiting_next_file] Found a new Shodan dump for day: ",
    #                 found_files,
    #                 flush=True,
    #             )
    #             return found_files
    #         elif mode == "latest":
    #             print(
    #                 "[INFO][waiting_next_file] Found a new Shodan dump for day: ",
    #                 found_files[-1],
    #                 flush=True,
    #             )
    #             return [found_files[-1]]

    #     return None

    # def compute_next_dump(self, last_date_commit):
    #     if last_date_commit:
    #         scheduler = croniter(CRON_EXPRESSION, last_date_commit)
    #         next_run = scheduler.get_next(datetime)
    #     else:
    #         next_run = datetime.now()
    #     return next_run

    def join_votes_shodan_df(self, df: DataFrame, datestr: str):
        assert time.strptime(datestr, "%Y-%m-%d")
        # version = self.datestr2version[datestr]
        # day_df = DeltaTable(self.tlhop_epss_report_fp, version=version).to_pandas()
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

        # Try join from most specific to least specific
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

        features_df["max_epss_cve_id"] = df["vulns"].apply(max_epss_cve_id)
        features_df["in_kev"] = features_df["max_epss_cve_id"].isin(self.kev_df["cveID"])
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
