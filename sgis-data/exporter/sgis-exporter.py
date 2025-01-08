#!/usr/bin/env python3

import argparse
import csv
import datetime
from ipaddress import IPv4Address
import logging
import os
import pathlib
import random
import sys
from typing import Any

import psycopg2
import sqlparse
from yacryptopan import CryptoPAn

DB_BATCH_SIZE = int(os.getenv("DB_BATCH_SIZE", 1000))
DB_NAME = os.getenv("DB_NAME", "fix")
DB_USER = os.getenv("DB_USER", "fix")
DB_PASS = os.getenv("DB_PASS", "fix")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", 5432)

NOTES_ANON_NUM = "ANON-NUM"
NOTES_ANON_IP = "ANON-IP"
NOTES_ANON_TEXT = "TEXT"
NOTES_TIMESTAMP = "TIMESTAMP"

MAX_ROWS_PER_TABLE = 10_000_000


class CountingAnonymizer:
    def __init__(self, table: str, column: str):
        self.table = str(table)
        self.column = str(column)
        self.value2id: dict[str, int] = {}

    def __call__(self, value: Any) -> int:
        return self.value2id.setdefault(str(value), len(self.value2id))


class TextAnonymizer:
    def __init__(self, table: str, column: str):
        self.table = str(table)
        self.column = str(column)

    def __call__(self, value: Any) -> int:
        return len(str(value))


class IPAnonymizer:
    __cryptopan = None

    def __init__(self, table: str, column: str):
        if IPAnonymizer.__cryptopan is None:
            # generate 32-char random string using random.sample:
            random_string = "".join(random.choices("0123456789abcdef", k=32))
            random_string = random_string.encode("utf-8")
            IPAnonymizer.__cryptopan = CryptoPAn(random_string)
        self.table = str(table)
        self.column = str(column)

    def __call__(self, value: Any) -> str:
        assert IPAnonymizer.__cryptopan is not None
        ipstr = str(value)
        if "/" in ipstr:
            ipstr, pfxlen = ipstr.split("/")
            anonip = IPAnonymizer.__cryptopan.anonymize(str(ipstr))
            return f"{anonip}/{pfxlen}"
        return IPAnonymizer.__cryptopan.anonymize(str(ipstr))


class NoAnonymizer:
    def __init__(self, table: str, column: str):
        self.table = str(table)
        self.column = str(column)

    def __call__(self, value: Any) -> Any:
        return str(value)


def generate_queries(
    csvfp: pathlib.Path,
    start_date: datetime.date,
    end_date: datetime.date,
    max_rows=MAX_ROWS_PER_TABLE,
) -> list[dict[str, Any]]:
    queries = []
    current_table = None
    gathered_columns: list[str] = []
    operations = []
    datatypes = []
    timestamp_column = None

    with open(csvfp, "r", encoding="utf8") as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            table_name = row["table_name"]
            column_name = row["column_name"]
            get = row["TRUE"]

            if current_table is not None and current_table != table_name:
                if table_name:
                    logging.debug(
                        "Table [%s] followed by [%s], ignoring columns",
                        current_table,
                        table_name,
                    )
                    current_table = table_name
                    gathered_columns = []
                    operations = []
                    datatypes = []
                    timestamp_column = None
                elif gathered_columns:
                    colstr = ",".join(gathered_columns)
                    if timestamp_column is not None:
                        sql = f"""SELECT {colstr} FROM {current_table} WHERE {timestamp_column} BETWEEN '{start_date.strftime("%Y-%m-%d")}' AND '{end_date.strftime("%Y-%m-%d")}' LIMIT {max_rows}"""
                    else:
                        sql = f"SELECT {colstr} FROM {current_table} LIMIT {max_rows}"
                    query = {
                        "table": current_table,
                        "columns": gathered_columns,
                        "operations": operations,
                        "datatypes": datatypes,
                        "timestamp_column": timestamp_column,
                        "sql": sql,
                    }
                    logging.info("%s", query["sql"])
                    queries.append(query)
                    current_table = None
                    gathered_columns = []
                    operations = []
                    datatypes = []
                    timestamp_column = None
                    continue

            if current_table is None:
                assert not gathered_columns
                current_table = table_name
            if get == "TRUE":
                gathered_columns.append(column_name)
                newtype: None | str = None
                if row["notes"] == NOTES_ANON_NUM:
                    operations.append(CountingAnonymizer(table_name, column_name))
                    datatypes.append("int")
                    newtype = "int"
                elif row["notes"] == NOTES_ANON_IP:
                    operations.append(IPAnonymizer(table_name, column_name))
                    datatypes.append("str")
                    newtype = "str"
                elif row["notes"] == NOTES_ANON_TEXT:
                    operations.append(TextAnonymizer(table_name, column_name))
                    datatypes.append("int")
                    newtype = "int"
                elif row["notes"] == NOTES_TIMESTAMP:
                    operations.append(NoAnonymizer(table_name, column_name))
                    datatypes.append(row["data_type"])
                    timestamp_column = column_name
                else:
                    operations.append(NoAnonymizer(table_name, column_name))
                    datatypes.append(row["data_type"])
                if newtype is not None:
                    logging.info(
                        "Retyping %s.%s from [%s] to %s",
                        table_name,
                        column_name,
                        row["data_type"],
                        newtype,
                    )

    logging.info("Generated %d queries", len(queries))

    return queries


def create_parser():
    parser = argparse.ArgumentParser(
        description="Export first 10 lines from targeted SGIS columns"
    )

    parser.add_argument(
        "--input",
        dest="inputfp",
        type=pathlib.Path,
        required=True,
        help="Path to CVS file specifying columns of interest",
    )
    parser.add_argument(
        "--start-date",
        dest="start_tstamp",
        type=str,
        required=True,
        help="Start date in YYYY-MM-DD format",
    )
    parser.add_argument(
        "--end-date",
        dest="end_tstamp",
        type=str,
        required=True,
        help="End date in YYYY-MM-DD format",
    )
    parser.add_argument(
        "--outdir",
        dest="outdir",
        type=pathlib.Path,
        required=False,
        help="Path to output directory [sgis--START--END]",
        default=None,
    )
    parser.add_argument(
        "--test",
        dest="testing",
        action="store_const",
        const=True,
        required=False,
        help="Perform a test run",
        default=False,
    )

    return parser


def get_cursor(testing: bool, gathered_columns: list[str], connection):
    if testing:
        assert connection is None
        return TestCursor(len(gathered_columns))
    return connection.cursor()


class TestCursor:
    def __init__(self, ncols: int):
        self.ncols = ncols
        self.fetched = False
        self.num = 0

    def execute(self, query: str) -> None:
        parsed = sqlparse.parse(query)
        if not parsed:
            raise RuntimeError(f"Generated an invalid SQL query: {query}")

    def fetchmany(self, _batchsz: int) -> list[tuple]:
        if self.fetched:
            return []
        self.fetched = True
        rows = []
        for i in range(10):
            self.num += 1
            string = IPv4Address(self.num)
            rows.append(tuple(string for _ in range(self.ncols)))
        return rows

    def close(self):
        pass


def setup_logging(outdir):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    file_handler = logging.FileHandler(outdir / "log.txt")
    stdout_handler = logging.StreamHandler(sys.stdout)

    file_handler.setLevel(logging.DEBUG)
    stdout_handler.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(formatter)
    stdout_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stdout_handler)


def process_query(query: dict[str, Any], args, connection):
    try:
        table_name = query["table"]
        gathered_columns = query["columns"]
        operations = query["operations"]
        colstr = ",".join(gathered_columns)
        cursor = get_cursor(args.testing, gathered_columns, connection)
        cursor.execute(query["sql"])

        with open(args.outdir / f"{table_name}.sql", "w", encoding="utf8") as outfd:
            while True:
                rows = cursor.fetchmany(DB_BATCH_SIZE)
                if not rows:
                    break
                for row in rows:
                    row = tuple(list(operations[i](v) for i, v in enumerate(row)))
                    stmt = f"INSERT INTO {table_name} ({colstr}) VALUES {row};\n"
                    outfd.write(stmt)
    except Exception as e:
        logging.exception("Exception when processing table %s", table_name, exc_info=e)
    finally:
        cursor.close()


def main():
    parser = create_parser()
    args = parser.parse_args()

    args.start_date = datetime.date.fromisoformat(args.start_tstamp)
    args.end_date = datetime.date.fromisoformat(args.end_tstamp)
    assert args.end_date > args.start_date

    if args.outdir is None:
        dn = f"sgis-{args.start_date.strftime('%Y%m%d')}-{args.end_date.strftime('%Y%m%d')}"
        args.outdir = pathlib.Path(dn)
    os.makedirs(args.outdir, exist_ok=True)
    print("Saving results to %s", args.outdir)

    setup_logging(args.outdir)

    logging.info("Exporting data between %s and %s", args.start_date, args.end_date)

    if DB_PASS == "fix" and not args.testing:
        logging.error("DB authentication variables not configured")
        logging.info("Please set DB auth variables at the beginning of the script")
        logging.info("Or set the DB_NAME, DB_USER, DB_PASS, DB_HOST, DB_PORT env vars")
        sys.exit(1)
    logging.info("DB_USER %s", DB_USER)

    queries = generate_queries(args.inputfp, args.start_date, args.end_date)

    connection: Any = None
    if not args.testing:
        connection = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            host=DB_HOST,
            port=DB_PORT,
        )

    for query in queries:
        process_query(query, args, connection)

    if not args.testing:
        connection.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception("Exception in main()", exc_info=e)
