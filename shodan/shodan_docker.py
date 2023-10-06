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


DOCKER_STATUSCODE_KEY = "StatusCode"
OUTDIR_CONTAINER_MOUNT = "/root/output"
SHODAN_TASK_LABEL_KEY = "shodan-task-id"


class ContainerState(enum.Enum):
    CREATED = "created"
    RESTARTING = "restarting"
    RUNNING = "running"
    REMOVING = "removing"
    PAUSED = "paused"
    EXITED = "exited"
    DEAD = "dead"

    def is_done(self):
        return self in [ContainerState.EXITED, ContainerState.DEAD]


@dataclasses.dataclass(frozen=True)
class ShodanConfig:
    output_dir: pathlib.Path
    shodan_api_key: str
    docker_image: str = "shodan-image"
    docker_poll_interval: float = 16.0
    docker_socket: str | None = None
    docker_timeout: int = 5


class Task(Protocol):
    label: str


@dataclasses.dataclass(frozen=True)
class ShodanTask:
    label: str
    ip_prefix: str


TaskCompletionCallback = Callable[[str, bool], None]


class ScanModule(Protocol):
    def __init__(self, config: Any, callback: TaskCompletionCallback) -> None:
        ...

    def enqueue(self, taskcfg: Task) -> None:
        ...

    def shutdown(self, wait: bool) -> None:
        ...


class Shodan(ScanModule):
    def __init__(self, config: ShodanConfig, callback: TaskCompletionCallback) -> None:
        def get_docker_client() -> docker.DockerClient:
            if config.docker_socket is None:
                return docker.from_env()
            return docker.DockerClient(base_url=config.docker_socket)

        self.config: ShodanConfig = config
        self.running: bool = True
        self.docker: docker.DockerClient = get_docker_client()
        self.containers: set = set()
        self.task_completion_callback = callback
        self.lock: threading.Lock = threading.Lock()
        self.thread: threading.Thread = threading.Thread(
            target=self.shodan_polling_thread,
            name="shodan-polling-thread",
        )
        self.thread.start()

    def enqueue(self, taskcfg: Task) -> None:
        assert isinstance(taskcfg, ShodanTask)
        outfp = self.config.output_dir / taskcfg.label
        os.makedirs(outfp, exist_ok=True)
        try:
            ctx = self.docker.containers.run(
                self.config.docker_image,
                command=["python", "./shodan_script.py", taskcfg.ip_address],
                detach=True,
                labels={SHODAN_TASK_LABEL_KEY: taskcfg.label},
                stdout=True,
                stderr=True,
                environment={"shodan_api_key": self.config.api_key},
                volumes={
                    str(outfp): {
                        "bind": OUTDIR_CONTAINER_MOUNT,
                        "mode": "rw",
                    },
                },
                working_dir="/root",
            )
        except docker.errors.APIError as e:
            logging.error("Shodan execution failed: %s", str(e))
            self.task_completion_callback(taskcfg.label, False)
            return
        with self.lock:
            self.containers.add((ctx, taskcfg))

    def shutdown(self, wait: bool = True) -> None:
        logging.info("Shodan shutting down (wait=%s)", wait)
        self.running = False
        if not wait:
            with self.lock:
                for ctx, cfg in self.containers:
                    logging.warning("Force-closing container for task %s", cfg.label)
                    ctx.remove(force=True)
            self.containers.clear()
        else:
            self.handle_finished_containers()
            self.thread.join()

        logging.info("Joined Shodan polling thread, module shut down")

    def shodan_polling_thread(self) -> None:
        while self.running or self.containers:
            self.handle_finished_containers()
            time.sleep(self.config.docker_poll_interval)
        logging.info("Shodan polling thread shutting down")

    def handle_finished_containers(self) -> None:
        completed = set()
        with self.lock:
            for ctx, cfg in self.containers:
                try:
                    ctx.reload()
                except docker.erros.NotFound:
                    logging.warning("Contanier not found: %s", cfg.label)
                    continue

                if not ContainerState(ctx.status).is_done():
                    continue

                assert cfg.label == ctx.labels[SHODAN_TASK_LABEL_KEY]

                r = ctx.wait(timeout=self.config.docker_timeout)
                r["stdout"] = ctx.logs(
                    stdout=True, stderr=False, timestamps=True
                ).decode("utf8")
                r["stderr"] = ctx.logs(
                    stdout=False, stderr=True, timestamps=True
                ).decode("utf8")
                outfp = self.config.output_dir / cfg.label
                with gzip.open(outfp / "result.json.gz", "wt", encoding="utf8") as fd:
                    json.dump(r, fd)
                self.task_completion_callback(cfg.label, True)
                logging.info(
                    "Shodan run completed, id %s status %d",
                    cfg.label,
                    r[DOCKER_STATUSCODE_KEY],
                )
                completed.add((ctx, cfg))

            self.containers -= completed

            logging.info(
                "Running %d ShodanSuite containers, waiting %d seconds to refresh",
                len(self.containers),
                self.config.docker_poll_interval,
            )
        for ctx, _cfg in completed:
            ctx.remove()
