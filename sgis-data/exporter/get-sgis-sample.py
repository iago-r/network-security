#!/usr/bin/env python3

import argparse
import csv
import logging
import os
import pathlib
import sys
import time
from typing import Any

import psycopg2
import sqlparse

DB_BATCH_SIZE = int(os.getenv("DB_BATCH_SIZE", 1000))
DB_NAME = os.getenv("DB_NAME", "fix")
DB_USER = os.getenv("DB_USER", "fix")
DB_PASS = os.getenv("DB_PASS", "fix")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", 5432)


def generate_queries(csvfp: pathlib.Path) -> list[dict[str, Any]]:
    queries = []
    current_table = None
    gathered_columns = []
    with open(csvfp, "r", encoding="utf8") as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            table_name = row["table_name"]
            column_name = row["column_name"]
            _data_type = row["data_type"]
            get = row["TRUE"]

            if current_table is not None and current_table != table_name:
                if table_name:
                    logging.warning(
                        "Table %s followed by %s, ignoring columns",
                        current_table,
                        table_name,
                    )
                    current_table = table_name
                    gathered_columns = []
                elif gathered_columns:
                    colstr = ",".join(gathered_columns)
                    query = {
                        "table": current_table,
                        "columns": gathered_columns,
                        "sql": f"SELECT {colstr} FROM {current_table} LIMIT 10;",
                    }
                    logging.debug("%s", query["sql"])
                    queries.append(query)
                    current_table = None
                    gathered_columns = []
                    continue

            if current_table is None:
                assert not gathered_columns
                current_table = table_name
            if get == "TRUE":
                gathered_columns.append(column_name)

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
        "--outdir",
        dest="outdir",
        type=pathlib.Path,
        required=False,
        help="Path to output directory [sgis-sample-%Y%m%d]",
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
    connection = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT,
    )
    return connection.cursor()


class TestCursor:
    def __init__(self, ncols: int):
        self.ncols = ncols
        self.fetched = False

    def execute(self, query: str) -> None:
        parsed = sqlparse.parse(query)
        if not parsed:
            raise RuntimeError(f"Generated an invalid SQL query: {query}")

    def fetchmany(self, _batchsz: int) -> list[tuple]:
        if self.fetched:
            return []
        self.fetched = True
        return [tuple("0" for _ in range(self.ncols))] * 10

    def close(self):
        pass


def main():
    logging.basicConfig(level=logging.DEBUG)

    parser = create_parser()
    args = parser.parse_args()

    if DB_PASS == "fix" and not args.testing:
        logging.error("DB authentication variables not configured")
        logging.info("Please set DB auth variables at the beginning of the script")
        logging.info("Or set the DB_NAME, DB_USER, DB_PASS, DB_HOST, DB_PORT env vars")
        sys.exit(1)
    logging.info("DB_USER %s", DB_USER)

    if args.outdir is None:
        args.outdir = pathlib.Path(time.strftime("sgis-sample-%Y%m%d", time.gmtime()))
    os.makedirs(args.outdir, exist_ok=True)
    logging.info("Saving results to %s", args.outdir)

    queries = generate_queries(args.inputfp)

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
        table_name = query["table"]
        gathered_columns = query["columns"]
        colstr = ",".join(gathered_columns)
        cursor = get_cursor(args.testing, gathered_columns, connection)
        cursor.execute(query["sql"])
        with open(args.outdir / f"{table_name}.sql", "w", encoding="utf8") as outfd:
            while True:
                rows = cursor.fetchmany(DB_BATCH_SIZE)
                if not rows:
                    break
                for row in rows:
                    stmt = f"INSERT INTO {table_name} ({colstr}) VALUES {row};\n"
                    outfd.write(stmt)
        cursor.close()

    if not args.testing:
        connection.close()


if __name__ == "__main__":
    main()
