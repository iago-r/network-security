#!/usr/bin/env python3

import logging
import pathlib
import sys
import time

from modules.api import Task

import nuclei


TEST_TARGETS = [
    "rubick.speed.dcc.ufmg.br",
    # "foreman.speed.dcc.ufmg.br",
]


def callback(task: Task, success: bool) -> None:
    logging.info("Callback for %s running, success=%s", task.label, success)


def main():
    logging.basicConfig(level=logging.INFO)

    logging.info("Starting Nuclei module")
    cfg = nuclei.NucleiConfig(
        callback=callback,
        storage_path=pathlib.Path("./output").absolute(),
        docker_poll_interval=1.0,
    )
    s = nuclei.Nuclei(cfg)

    logging.info("Submitting tasks to Nuclei")
    for target in TEST_TARGETS:
        name = target.split(".")[0]
        taskcfg = nuclei.NucleiTask(
            label=time.strftime(f"{name}-%Y%m%d-%H%M%S"),
            target=target,
        )
        s.enqueue(taskcfg)
    logging.info("Tasks submitted")

    logging.info("Waiting for Nuclei to shut down")
    s.shutdown(wait=True)


if __name__ == "__main__":
    sys.exit(main())
