#!/usr/bin/env python3

import logging
import os
import pathlib
import sys
import time

import scout

import argparse

parser = argparse.ArgumentParser()
parser.add_argument(
    "-t1", "--test1", type=int, help="Test 1: Container removed after n seconds."
)
parser.add_argument(
    "-t2",
    "--test2",
    type=int,
    help="Test 2: Container with infinite execution removed after n seconds.",
)
parser.add_argument(
    "-t3",
    "--test3",
    type=int,
    help="Test 3: Container removed after returning an error.",
)

parser.add_argument(
    "-scout",
    "--scout_suite",
    action="store_true",
    help="SCOUT: Running the Scout module.",
)

args = parser.parse_args()


CWD = pathlib.Path(os.getcwd())
assert pathlib.Path(CWD / __file__).exists(), "Run from inside tests/ with ./testrun.py"
SCOUT_MOD_PATH = CWD.parent


DOCKER_STATUSCODE_KEY = "StatusCode"
OUTDIR_CONTAINER_MOUNT = "/root/output"
SCOUT_TASK_LABEL_KEY = "scout-task-id"


def callback(label: str, success: bool) -> None:
    logging.info("Callback for %s running, success=%s", label, success)


def test_scout(s):
    taskcfg = scout.ScoutTask(
        time.strftime("scout-%Y%m%d-%H%M%S"),
        f"scout aws --no-browser --result-format json \
        --report-dir {OUTDIR_CONTAINER_MOUNT} --logfile \
        {OUTDIR_CONTAINER_MOUNT}/scout.log",  # Commands_scout
        volumes={
            "./dev/aws-credentials": {"bind": "/root/.aws/credentials", "mode": "ro"},
            "./data": {"bind": "/root/output", "mode": "rw"},
        },  # volumes_scout
    )

    logging.info("RUNNING TEST SCOUT")
    s.enqueue(taskcfg)
    logging.info("Task submitted")
    s.shutdown()


def task_1(s, seconds: int):
    taskcfg = scout.ScoutTask(
        time.strftime("scout-%Y%m%d-%H%M%S"),
        f"sleep {seconds}",  # commands
    )

    taskcfg2 = scout.ScoutTask(time.strftime("scout-%Y%m%d-%H%M%S"), f"sleep 5")

    logging.info(
        "RUNNING TEST 1 - The container was removed after n seconds, along with another set of tasks."
    )
    s.enqueue(taskcfg)
    s.enqueue(taskcfg2)
    logging.info("Task submitted")
    s.shutdown()


def task_2(s, seconds: int):
    taskcfg = scout.ScoutTask(
        time.strftime("scout-%Y%m%d-%H%M%S"),
        "tail -f /dev/null",  # commands
    )

    logging.info(
        "RUNNING TEST 2 - Container with infinite execution removed after n seconds."
    )
    s.enqueue(taskcfg)

    time.sleep(seconds)
    logging.info("Task submitted")
    s.shutdown(False)


def task_3(s, seconds: int):
    taskcfg = scout.ScoutTask(
        time.strftime("scout-%Y%m%d-%H%M%S"),
        f"sh -c 'sleep {seconds} && exit 1'",
    )

    logging.info("RUNNING TEST 3 - Container removed after returning an error.")
    s.enqueue(taskcfg)

    logging.info("Task submitted")
    s.shutdown()


scout_image = "rossja/ncc-scoutsuite:aws-latest"
generic_image = "alpine"


def main():
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Scout module")
    cfg = scout.ScoutConfig(
        pathlib.Path(SCOUT_MOD_PATH / "dev/aws-credentials"),
        pathlib.Path(SCOUT_MOD_PATH / "data"),
        docker_image=scout_image,
        docker_poll_interval=1.0,
    )
    logging.info("Scout module started")
    s = scout.Scout(cfg, callback)
    logging.info("Submitting task to Scout module")

    # python3 testrun.py -t1 "tempo de execução em segundos"
    if args.test1:
        seconds = args.test1
        task_1(s, seconds)

    # #python3 testrun.py -t2 "tempo de execução em segundos"
    if args.test2:
        seconds = args.test2
        task_2(s, seconds)

    # python3 testrun.py -t3 "tempo de execução em segundos"
    if args.test3:
        seconds = args.test3
        task_3(s, seconds)

    # python3 testrun.py -scout
    if args.scout_suite:
        test_scout(s)


if __name__ == "__main__":
    sys.exit(main())
