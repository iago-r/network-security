from __future__ import annotations

import enum
from typing import Callable, Protocol


class ScanModule(Protocol):
    """The ScanModule API

    The controller calls ScanModule.__init__() to instantiate a new
    module.  The new module is in charge of running any needed
    preparations to start running tasks.  In particular, modules should
    start a control thread to handle its background tasks.

    Check the documentation of each module to find out how to configure
    it or create new tasks.

    The enqueue() functions must be nonblocking.  Tasks should be run in
    the background, and their completion notified to the controller by
    calling the completion callback received in the configuration.

    Errors arising from tasks, e.g., execution failures due to crashes
    of the background processes, *must not* be propagated to the
    controller.  Any failure in task execution should be handled by the
    module, and notified through the completion callback.  Errors
    arising during initialization (i.e., inside __init__) or from from
    incorrect or incompatible calls from the controller *should* raise
    exceptions so the controller can fix the issue."""

    def __init__(self, config: Config) -> None:
        ...
    def enqueue(self, taskcfg: Task) -> None:
        ...
    def shutdown(self, wait: bool) -> None:
        """Shut down the module

        This function is allowed to block.  If wait=False, then
        shutdown() is expected to finish reasonably fast by cancelling
        or disowning any background tasks.  If wait=True, then the
        module should wait for ongoing tasks to terminate before
        shutdown."""
        ...


class Task(Protocol):
    label: str


TaskCompletionCallback = Callable[[Task, bool], None]
"""Callback to notify the controller a Task finished execution

The TaskCompletionCallback receives as parameters the finished task and
a boolean indicating whether it has finished successfully or not.
"""


class Config(Protocol):
    name: str
    callback: TaskCompletionCallback


class DockerContainer:
    class State(enum.Enum):
        """Enumeration of Docker container states

        These are taken verbatim from
        https://docs.docker.com/engine/reference/commandline/ps/ and are
        processed from plain strings.  When Python 3.11 is available, we
        should update this to use `enum.StrEnum`."""

        CREATED = "created"
        RESTARTING = "restarting"
        RUNNING = "running"
        REMOVING = "removing"
        PAUSED = "paused"
        EXITED = "exited"
        DEAD = "dead"

        def is_done(self):
            return self in [DockerContainer.State.EXITED, DockerContainer.State.DEAD]

    @staticmethod
    def get_status_code(results) -> str:
        """Get the exit status code of a container"""
        return results["StatusCode"]
