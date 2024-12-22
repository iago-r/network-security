from datetime import datetime, timedelta
import logging
import os
from pathlib import Path
import re
from typing import Optional

from deltalake import DeltaTable
import pandas as pd
import psycopg2


RETENTION_VACUUM_HOURS = 24 * 7
RETENTION_VACUUM_TIMEDELTA = timedelta(hours=RETENTION_VACUUM_HOURS)


class DatasetManager:
    def __init__(self, tlhop_epss_report_fp: Path, tlhop_epss_views_fp: Path):
        self.datestr2version = {}
        self.tlhop_epss_report_fp: Path = tlhop_epss_report_fp
        self.tlhop_epss_views_fp: Path = tlhop_epss_views_fp
        self.n_views = 3
        self.sampled_data = None
        assert self.tlhop_epss_report_fp.exists()
        assert self.tlhop_epss_views_fp.exists()
        self.table: DeltaTable = DeltaTable(self.tlhop_epss_report_fp)

    def load_datasets(self):
        write_commits = 0
        last_vacuum_tstamp = None

        for commit in self.table.history():
            # iterates over commits in reverse cronological order:
            operation = commit.get("operation", "")
            if operation == "WRITE":
                write_commits += 1
                commit_tstamp = datetime.fromtimestamp(commit["timestamp"] / 1e3)

                if "userMetadata" in commit:
                    filename = os.path.basename(commit["userMetadata"])
                    day = re.findall(r"\d+", filename)[0]
                    commit_datestr = day[0:4] + "-" + day[4:6] + "-" + day[6:8]
                else:
                    commit_datestr = commit_tstamp.strftime("%Y-%m-%d")

                if last_vacuum_tstamp is None or commit_tstamp > last_vacuum_tstamp:
                    if commit_datestr in self.datestr2version:
                        logging.warning("Overwriting commit on %s", commit_datestr)
                    self.datestr2version[commit_datestr] = commit["version"]
                else:
                    message = "Commit %s from %s too old, ignoring"
                    logging.debug(message, commit["version"], commit_datestr)

            elif operation == "VACUUM END" and last_vacuum_tstamp is None:
                commit_tstamp = datetime.fromtimestamp(commit["timestamp"] / 1e3)
                last_vacuum_tstamp = commit_tstamp - RETENTION_VACUUM_TIMEDELTA

        logging.info(
            "Selected %d of %d commits, start=%s end=%s",
            len(self.datestr2version),
            write_commits,
            min(self.datestr2version.keys()),
            max(self.datestr2version.keys()),
        )

    def last_write_commit_tstamp(self) -> Optional[datetime]:
        for commit in self.table.history():
            if commit.get("operation", "") == "WRITE":
                return datetime.fromtimestamp(commit["timestamp"] / 1e3)
        return None

    def get_sorted_dates(self) -> list[str]:
        return sorted(list(self.datestr2version.keys()), reverse=True)

    def get_last_write_dump_datestr(self) -> Optional[str]:
        if dates := self.get_sorted_dates():
            return dates[0]
        return None

    # def retrive_commit(self, day):
    #     return self.available_datasets.get(day, -1)

    def get_view_dataset(self, datestr: str, code):
        if version := self.datestr2version[datestr]:
            filepath = self.tlhop_epss_views_fp_template.format(code)
            logging.debug("Loading view from %s", filepath)
            return DeltaTable(filepath, version=version).to_pandas()
        else:
            return pd.DataFrame()

    def get_report_dataset(
        self,
        datestr: str,
        columns: Optional[list[str]] = None,
        condition=None,
    ):
        if version := self.datestr2version.get(datestr):
            return (
                DeltaTable(self.tlhop_epss_report_fp, version=version)
                .to_pyarrow_dataset()
                .to_table(filter=condition, columns=columns)
                .to_pandas()
            )
        else:
            msg = "Tried to access nonexistent commit %s on %s"
            logging.warning(msg, datestr, self.tlhop_epss_report_fp)
            return pd.DataFrame()

    def get_report_dataset_new(
        self,
        day,
        columns=None,
        condition=None,
        single_output=False,
        start=0,
        finish=-1,
        sort_by="score",
        ascending=False,
    ):
        commit = self.retrive_commit(day)
        df = None
        if commit >= 0:
            filepath = self.tlhop_epss_report_path

            print(f"Reading report of day {day}")
            dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()

            if single_output:
                df = dt.filter(condition).head(1).to_pydict()
            else:
                table = dt.to_table(filter=condition, columns=None)
                df = table.to_pandas()
                # df['score'] = df['vulns_scores'].apply(lambda x: x.get('epss', []) if isinstance(x, dict) else [])
                # df['score'] = df['score'].apply(lambda probs: 1 - np.prod([1 - p for p in probs]))
                df["score"] = df["vulns_scores"].apply(
                    lambda x: max(x.get("epss", [0])) if isinstance(x, dict) else 0
                )
                df = df.drop(columns=["vulns_scores"])
                # df = df.sort_values(by=sort_by, ascending=ascending)

                # Sample 600 random entries
                df = df.sample(n=600, random_state=42)

                if finish > 0:
                    df = df.iloc[start:finish]

            file_path = "file_ips.csv"
            df.to_csv(file_path, index=False)
            print(f"DataFrame saved to {file_path} successfully.")

        return df

    def sample_data(self, day, random_state, entries):
        """
        Sample N random entries from the dataset and store them
        """
        commit = self.retrive_commit(day)

        if commit >= 0:
            filepath = self.tlhop_epss_report_path

            print(
                f"[### SAMPLE_DATA ###] Sampling data for each user: {day} - Random state: {random_state}"
            )
            dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()

            table = dt.to_table(columns=None)
            df = table.to_pandas()

            df["score"] = df["vulns_scores"].apply(
                lambda x: max(x.get("epss", [0])) if isinstance(x, dict) else 0
            )
            df = df.drop(columns=["vulns_scores"])
            # df = df.sort_values(by=sort_by, ascending=ascending)

            # self.sampled_data = df.sample(n=600, random_state=42)
            self.sampled_data = df.sample(n=entries, random_state=random_state)

        else:
            self.sampled_data = pd.DataFrame()

    def get_report_each(
        self,
        day,
        user_id=None,
        columns=None,
        condition=None,
        single_output=False,
        start=0,
        finish=-1,
        sort_by="score",
        ascending=False,
    ):
        """
        Fetch 120 entries for each user from pre-sampled data.
        If the data is not yet sampled for the current day, it will sample it first.
        """
        if self.sampled_data is None:
            self.sample_data(day, 777, 600)

        if self.sampled_data is not None:
            print(f"Using pre-sampled data for day {day} for user {user_id}")
            df = self.sampled_data.copy()

            if single_output:
                df_filtered = df.query(condition) if condition else df
                df = df_filtered.head(1).to_dict(orient="records")
            else:
                if condition:
                    df = df.query(condition)

                # df = df.sort_values(by=sort_by, ascending=ascending)

                num_users = 6
                entries_per_user = 120

                user_index = user_id % num_users
                start_index = user_index * entries_per_user
                end_index = start_index + entries_per_user

                df = df.iloc[start_index:end_index]

                if finish > 0:
                    df = df.iloc[start:finish]
        else:
            df = pd.DataFrame()

        return df

    def get_total_entries_new(self, day, condition=None):
        commit = self.retrive_commit(day)
        total_entries = 0
        if commit >= 0:
            filepath = self.tlhop_epss_report_path
            dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()
            if condition:
                total_entries = dt.filter(condition).count_rows()
            else:
                total_entries = dt.count_rows()
        return total_entries

    def remove_old_data(self):
        # default of 1 week
        filepaths = [self.tlhop_epss_report_path] + [
            self.tlhop_epss_views_path.format(code + 1) for code in range(self.n_views)
        ]

        for filepath in filepaths:
            filepath = filepath.replace("//", "/")
            print(
                f"[INFO][DatasetManager][remove_old_data] - checking file {filepath}",
                flush=True,
            )
            try:
                dt = DeltaTable(filepath)
                dt.vacuum(
                    retention_hours=RETENTION_VACUUM_HOURS,
                    dry_run=False,
                    enforce_retention_duration=False,
                )
            except:
                print(
                    f"[ERROR][DatasetManager][remove_old_data] - error to vacuum file '{filepath}'",
                    flush=True,
                )

    def waiting_next_file(self, mode="latest"):
        next_date = self.last_dump_date().replace("-", "")

        filepath = SHODAN_FOLDER + "/BR.{pattern}.json.bz2"
        available_dates = [
            os.path.basename(s)[3:-9]
            for s in sorted(glob.glob(filepath.format(pattern="*")))
        ]

        found_files = [
            day[0:4] + "-" + day[4:6] + "-" + day[6:8]
            for day in available_dates
            if next_date < day
        ]
        if len(found_files) > 0:
            if mode == "all":
                print(
                    "[INFO][waiting_next_file] Found a new Shodan dump for day: ",
                    found_files,
                    flush=True,
                )
                return found_files
            elif mode == "latest":
                print(
                    "[INFO][waiting_next_file] Found a new Shodan dump for day: ",
                    found_files[-1],
                    flush=True,
                )
                return [found_files[-1]]

        return None

    def compute_next_dump(self, last_date_commit):
        if last_date_commit:
            scheduler = croniter(CRON_EXPRESSION, last_date_commit)
            next_run = scheduler.get_next(datetime)
        else:
            next_run = datetime.now()
        return next_run

    def search_by_meta_id(self, day, meta_id):
        """
        Search for a specific meta_id in the dataset and return the corresponding information.
        """
        commit = self.retrive_commit(day)
        if commit >= 0:
            filepath = self.tlhop_epss_report_path

            dt = DeltaTable(filepath, version=commit).to_pyarrow_dataset()

            condition = ds.field("meta_id") == meta_id

            result = dt.to_table(filter=condition).to_pandas()

            if not result.empty:
                a = "a"
            else:
                print(f"[INFO] No data found for meta_id {meta_id}.")

            return result
        else:
            print(f"[ERROR] No dataset available for day {day}")
            return pd.DataFrame()

    def update_merged_df_with_search_results(self, merged_df, day):
        for index, row in merged_df.iterrows():
            meta_id = row["meta_id"]

            search_result = self.search_by_meta_id(day, meta_id)

            if not search_result.empty:
                for col in search_result.columns:
                    if col in merged_df.columns:
                        merged_df.at[index, col] = search_result[col].values[0]
                    else:
                        merged_df[col] = None
                        merged_df.at[index, col] = search_result[col].values[0]
            else:
                print(
                    f"[INFO] No result found for meta_id {meta_id}. Skipping row {index}."
                )

        return merged_df

    @staticmethod
    def psql_read_table(
        dbtable: str,
        host: str = "127.0.0.1",
        dbname: str = "postgres",
        user: str = "postgres",
        passwd: str = "",
        port: int = 5432,
    ) -> pd.DataFrame:
        connection = psycopg2.connect(
            host=host,
            database=dbname,
            user=user,
            password=passwd,
            port=port,
        )
        cursor = connection.cursor()
        query = f"SELECT * FROM {dbtable};"
        df = pd.read_sql(query, connection)
        logging.info("Read table %s from PostgreSQL, %d rows", dbtable, df.count())
        cursor.close()
        connection.close()
        return df
