#!/usr/bin/env python3

import logging
import os
import pathlib
import sys
import time

import scout


CWD = pathlib.Path(os.getcwd())
assert pathlib.Path(CWD / __file__).exists(), "Run from inside tests/ with ./testrun.py"
SCOUT_MOD_PATH = CWD.parent


def callback(label: str, success: bool) -> None:
    logging.info("Callback for %s running, success=%s", label, success)


def main():
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Scout module")
    cfg = scout.ScoutConfig(
        pathlib.Path(SCOUT_MOD_PATH / "dev/aws-credentials"),
        pathlib.Path(SCOUT_MOD_PATH / "data"),
        # docker_image="hello-world",
        docker_poll_interval=1.0,
    )
    logging.info("Scout module started")
    s = scout.Scout(cfg, callback)
    logging.info("Submitting task to Scout module")
    taskcfg = scout.ScoutTask(
        time.strftime("scout-%Y%m%d-%H%M%S"),
    )
    s.enqueue(taskcfg)
    logging.info("Task submitted")
    s.shutdown()


if __name__ == "__main__":
    sys.exit(main())
