#!/usr/bin/env python3

import logging
import os
import pathlib
import sys
import time

import shodan_script


CWD = pathlib.Path(os.getcwd())
assert pathlib.Path(CWD / __file__).exists(), "Run from inside tests/ with ./testrun.py"
SHODAN_MOD_PATH = CWD.parent


def callback(label: str, success: bool) -> None:
    logging.info("Callback for %s running, success=%s", label, success)


def test_shodan(s, taskcfg):
    commands_shodan = ["ip_address", "python", "./shodan2.py", taskcfg.ip_address]

    logging.info("RUNNING TEST_SHODAN")
    s.enqueue(taskcfg, commands_shodan)
    logging.info("Task submitted")
    s.shutdown()


def main():
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Shodan module")
    cfg = shodan_script.ShodanConfig(
        pathlib.Path(SHODAN_MOD_PATH / "dev/shodan-credentials"),
        pathlib.Path(SHODAN_MOD_PATH / "data"),
        docker_image="shodan-image",
        docker_poll_interval=1.0,
    )
    logging.info("Shodan module started")
    s = shodan_script.Shodan(cfg, callback)
    logging.info("Submitting task to Shodan module")
    taskcfg = shodan_script.ShodanTask(
        time.strftime("shodan-%Y%m%d-%H%M%S"), "ip_address"
    )

    test_shodan(s, taskcfg)


if __name__ == "__main__":
    sys.exit(main())
