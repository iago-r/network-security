#!/usr/bin/env python3

from __future__ import annotations

import dataclasses
import enum
import gzip
import json
import logging
import os
import pathlib
import threading
import time
from typing import Any, Callable, Protocol

import docker

from modules.api import (
    ScanModule,
    Config,
    Task,
    TaskCompletionCallback,
    DockerContainer,
)


# OUTDIR_CONTAINER_MOUNT = "/root/output"
NUCLEI_TASK_LABEL_KEY = "nuclei-task-id"
NUCLEI_TEMPLATES_PATH = pathlib.Path("~/data/nuclei-templates/").expanduser()
NUCLEI_TEMPLATES_MOUNTPOINT = pathlib.Path("/root/nuclei-templates")


@dataclasses.dataclass(frozen=True)
class NucleiConfig(Config):
    callback: TaskCompletionCallback
    temp_storage_path: pathlib.Path
    name: str = "nuclei-default"
    docker_image: str = "projectdiscovery/nuclei:v2.9.6"
    docker_poll_interval: float = 16.0
    docker_socket: str | None = None
    docker_timeout: int = 5
    templates_path: pathlib.Path = NUCLEI_TEMPLATES_PATH


@dataclasses.dataclass(frozen=True)
class NucleiTask(Task):
    label: str
    targets: list[str]
    templates: list[str]


class Nuclei(ScanModule):
    def __init__(self, config: NucleiConfig) -> None:
        def get_docker_client() -> docker.DockerClient:
            if config.docker_socket is None:
                return docker.from_env()
            return docker.DockerClient(base_url=config.docker_socket)

        self.config: NucleiConfig = config
        self.docker: docker.DockerClient = get_docker_client()
        self.logger = logging.getLogger(self.config.name)
        self.logger.setLevel(logging.DEBUG)

        self.running: bool = True
        self.containers: set = set()
        self.lock: threading.RLock = threading.RLock()
        self.queue: list[NucleiTask] = []
        self.queuecond: threading.Condition = threading.Condition()

        self.polling_thread: threading.Thread = threading.Thread(
            target=self.nuclei_polling_thread,
            name=f"{self.config.name}:polling",
        )
        self.polling_thread.start()
        self.launcher_thread: threading.Thread = threading.Thread(
            target=self.nuclei_launcher_thread,
            name=f"{self.config.name}:launcher",
        )
        self.launcher_thread.start()

    def enqueue(self, taskcfg: NucleiTask) -> None:
        assert isinstance(taskcfg, NucleiTask)
        assert self.running
        with self.queuecond:
            self.queue.append(taskcfg)
            self.queuecond.notify()

    def shutdown(self, wait: bool = True) -> None:
        logging.info("Module shutting down (wait=%s)", wait)
        self.running = False
        self.handle_finished_containers()

        if not wait:
            with self.lock:
                for ctx, cfg in self.containers:
                    logging.warning("Force-closing container for task %s", cfg.label)
                    ctx.remove(force=True)
                self.containers = set()
        logging.info("Joining polling thread")
        self.polling_thread.join()

        with self.queuecond:
            self.queuecond.notify()
        self.logger.info("Joining launcher thread")
        self.launcher_thread.join()

        logging.info("Joined threads, shutdown complete")

    def nuclei_launcher_thread(self) -> None:
        self.update_templates()
        while self.running:
            with self.queuecond:
                if self.queue:
                    launching = self.queue
                    self.queue = []
                else:
                    logging.debug("nuclei_launcher_thread waiting next task")
                    self.queuecond.wait()
                    continue
            logging.debug("nuclei_launcher_thread launching %d tasks", len(launching))
            for taskcfg in launching:
                self.launch_task(taskcfg)
        logging.info("nuclei_launcher_thread exiting, %d tasks dropped", len(self.queue))

    def nuclei_polling_thread(self) -> None:
        while self.running or self.containers:
            self.handle_finished_containers()
            time.sleep(self.config.docker_poll_interval)
        logging.info("nuclei_polling_thread shutting down")

    def update_templates(self) -> None:
        self.logger.info("update_templates starting")
        start = time.time()
        os.makedirs(self.config.templates_path, exist_ok=True)
        try:
            logs = self.docker.containers.run(
                self.config.docker_image,
                command=[
                    # "-update-templates",
                    # "-templates-version",
                    # "-tl",
                    # f"-ud={NUCLEI_TEMPLATES_MOUNTPOINT}",
                    "-target",
                    "rubick.speed.dcc.ufmg.br",
                    # "-t",
                    # "/root/nuclei-templates/network/cves",
                    # "/root/nuclei-templates/network/detection/sshd-dropbear-detect.yaml",
                    "-disable-update-check",
                ],
                detach=False,
                stdout=False,
                stderr=True,
                labels={NUCLEI_TASK_LABEL_KEY: "nuclei-update-templates"},
                volumes={
                    str(self.config.templates_path): {
                        "bind": str(NUCLEI_TEMPLATES_MOUNTPOINT),
                        "mode": "rw",
                    },
                },
            )
        except docker.errors.APIError as e:
            logging.error("Scout execution failed: %s", str(e))
            self.task_completion_callback(taskcfg.label, False)
            return
        runtime = time.time() - start
        self.logger.info("update_templates terminated in %.03fs", runtime)
        self.logger.debug(logs.decode("utf8"))

    def launch_task(self, taskcfg: NucleiTask) -> None:
        outfp = self.config.temp_storage_path / taskcfg.label
        os.makedirs(outfp, exist_ok=True)
        try:
            ctx = self.docker.containers.run(
                self.config.docker_image,
                command=[
                    # "-update-templates",
                    # "-templates-version",
                    # "-tl",
                    # f"-ud={NUCLEI_TEMPLATES_MOUNTPOINT}",
                    "-target",
                    "rubick.speed.dcc.ufmg.br",
                    # "-t",
                    # "/root/nuclei-templates/network/cves",
                    # "/root/nuclei-templates/network/detection/sshd-dropbear-detect.yaml",
                    "-disable-update-check",
                ],
                detach=True,
                labels={SCOUT_TASK_LABEL_KEY: taskcfg.label},
                stdout=True,
                stderr=True,
                volumes={
                    str(self.config.credentials_file): {
                        "bind": "/root/.aws/credentials",
                        "mode": "ro",
                    },
                    str(outfp): {
                        "bind": OUTDIR_CONTAINER_MOUNT,
                        "mode": "rw",
                    },
                },
                working_dir="/root",
            )
        except docker.errors.APIError as e:
            logging.error("Scout execution failed: %s", str(e))
            self.task_completion_callback(taskcfg.label, False)
            return
        with self.lock:
            self.containers.add((ctx, taskcfg))

    def handle_finished_containers(self) -> None:
        completed = set()
        with self.lock:
            for ctx, cfg in self.containers:
                ctx.reload()
                if not DockerContainer.State(ctx.status).is_done():
                    continue
                assert cfg.label == ctx.labels[NUCLEI_TASK_LABEL_KEY]
                r = ctx.wait(timeout=self.config.docker_timeout)
                outfp = self.config.temp_storage_path / cfg.label
                stdout = ctx.logs(stdout=True, stderr=False).decode("utf8")
                stderr = ctx.logs(stdout=False, stderr=True).decode("utf8")
                with gzip.open(outfp / "stdout.txt.gz", "wt", encoding="utf8") as fd:
                    fd.write(stdout)
                with gzip.open(outfp / "stderr.txt.gz", "wt", encoding="utf8") as fd:
                    fd.write(stderr)
                with gzip.open(outfp / "docker.json.gz", "wt", encoding="utf8") as fd:
                    json.dump(r, fd)
                self.config.callback(cfg.label, True)
                logging.info(
                    "Nuclei task completed, id %s status %s",
                    cfg.label,
                    DockerContainer.get_status_code(ctx),
                )
                completed.add((ctx, cfg))
            self.containers -= completed
            logging.info(
                "Running %d Nuclei containers, waiting %d seconds to refresh",
                len(self.containers),
                self.config.docker_poll_interval,
            )
        for ctx, _cfg in completed:
            ctx.remove()
