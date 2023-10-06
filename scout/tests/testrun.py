#!/usr/bin/env python3

import argparse
import logging
import os
import pathlib
import sys
import time

import scout

import json


ALPINE_IMAGE = "alpine"
NUM_CONTAINERS = 5
BASE_SLEEP_DURATION = 8
SLEEP_INCREMENT = 3


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cred-file",
        dest="cred_file",
        metavar="FILE",
        type=pathlib.Path,
        help="Path to AWS credentials file [%(default)s]",
        default=pathlib.Path("~/.aws/credentials").expanduser(),
        required=False,
    )
    parser.add_argument(
        "-t", "--test",
        action="append",
        dest="tests",
        type=int,
        choices=[1, 2, 3],
        help="The tests to run, can be used multiple times %(default)s",
        default=[],
        required=False,
    )
    parser.add_argument(
        "--run-scout",
        action="store_true",
        help="Run Scout on AWS account in addition to tests [%(default)s]",
        default=False,
        required=False,
    )
    parser.add_argument(
        "--outdir",
        dest="outdir",
        metavar="DIR",
        type=pathlib.Path,
        help="Where to store test output",
        default=pathlib.Path("./test-output").absolute(),
        required=False,
    )
    return parser


def callback(label: str, success: bool) -> None:
    logging.info("Callback for %s running, success=%s", label, success)

def get_rolearn(label: str) -> str:
    with open("exception.json", "r",encoding="utf8") as file:
        data = json.load(file)    
    return data[label]


def run_scout(cfg: scout.ScoutConfig):

    data_rolearn = get_rolearn('role-arn')

    logging.info("Starting Scout module")
    sm = scout.Scout(cfg, callback)

    taskcfg = scout.ScoutTask("scout-run",  
        role_arn= data_rolearn       
    )
    logging.info("Running Scout")
    sm.enqueue(taskcfg)
    logging.info("Waiting for Scout to terminate")
    sm.shutdown(wait=True)


def run_test_1(cfg: scout.ScoutConfig) -> None:
    logging.info("Starting Scout module")
    sm = scout.Scout(cfg, callback)

    logging.info("Running test 1")
    logging.info("Will start %d containers", NUM_CONTAINERS)
    for i in range(1, NUM_CONTAINERS+1):
        taskcfg = scout.ScoutTask(
            f"test-1-{i}",
            ("sleep", f"{BASE_SLEEP_DURATION + SLEEP_INCREMENT*i}"),
        )
        sm.enqueue(taskcfg)

    logging.info("Waiting for all containers to terminate cleanly")
    sm.shutdown(wait=True)
    logging.info("Test 1 completed")


def run_test_2(cfg: scout.ScoutConfig):
    logging.info("Starting Scout module")
    sm = scout.Scout(cfg, callback)

    logging.info("Running test 2")
    logging.info("Will start %d containers", NUM_CONTAINERS)
    for i in range(1, NUM_CONTAINERS+1):
        taskcfg = scout.ScoutTask(
            f"test-2-{i}",
            ("sleep", f"{BASE_SLEEP_DURATION + SLEEP_INCREMENT*i}"),
        )
        sm.enqueue(taskcfg)

    logging.info("Sleeping %d seconds", BASE_SLEEP_DURATION)
    time.sleep(BASE_SLEEP_DURATION)
    logging.info("Force-quitting remaining containers")
    sm.shutdown(wait=False)
    logging.info("Test 2 completed")


def run_test_3(cfg: scout.ScoutConfig) -> None:
    logging.info("Starting Scout module")
    sm = scout.Scout(cfg, callback)

    logging.info("Running test 3")
    logging.info("Will start %d containers", NUM_CONTAINERS)
    for i in range(1, NUM_CONTAINERS+1):
        taskcfg = scout.ScoutTask(
            f"test-3-{i}",
            ("sh", "-c", f"sleep {BASE_SLEEP_DURATION + SLEEP_INCREMENT*i} && false"),
        )
        sm.enqueue(taskcfg)

    logging.info("Waiting for all containers to fail")
    sm.shutdown(wait=True)
    logging.info("Test 3 completed")


TEST_FUNCTIONS = [run_test_1, run_test_2, run_test_3]


def main():
    parser = create_parser()
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    cfg = scout.ScoutConfig(
        args.cred_file,
        args.outdir,
        dockertaskcfg_image=ALPINE_IMAGE,
        docker_poll_interval=1.0,
    )

    logging.info("Running tests")
    for test in args.tests:
        TEST_FUNCTIONS[ test - 1 ](cfg)

    if args.run_scout:
        run_scout(cfg)

    logging.info("Done")


if __name__ == "__main__":
    sys.exit(main())
