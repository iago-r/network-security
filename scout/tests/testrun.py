#!/usr/bin/env python3

import logging
import os
import pathlib
import sys
import time

import scout

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-t1', '--task1', type=int ,help='Task 1')
parser.add_argument('-t2', '--task2', type=int , help='Task 2')
parser.add_argument('-t3', '--task3', type=int , help='Task 3')
args = parser.parse_args()


CWD = pathlib.Path(os.getcwd())
assert pathlib.Path(CWD / __file__).exists(), "Run from inside tests/ with ./testrun.py"
SCOUT_MOD_PATH = CWD.parent


def callback(label: str, success: bool) -> None:
    logging.info("Callback for %s running, success=%s", label, success)

def task_1(s, taskcfg, seconds: int):
    task_generic_sleep = ["sleep", f'{1}']
    logging.info("")
    logging.info("RUNNING TASK 1")
    s.enqueue(taskcfg, task_generic_sleep, seconds)
    logging.info("Task submitted")
    s.shutdown()

def task_2(s, taskcfg, seconds: int):
    task_generic_inf = ["tail", "-f" ,"/dev/null"]
    logging.info("")
    logging.info("RUNNING TASK 2")
    s.enqueue(taskcfg, task_generic_inf)
    time.sleep(seconds)
    logging.info("Task submitted")
    s.shutdown(False)

def task_3(s, taskcfg, seconds: int):
    task_generic_error = ["sh", "-c", f'sleep {seconds}', "&&" , "exit", "1"]
    logging.info("")
    logging.info("RUNNING TASK 3")
    s.enqueue(taskcfg, task_generic_error)
    logging.info("Task submitted")
    s.shutdown()



def main():
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Scout module")
    cfg = scout.ScoutConfig(
        pathlib.Path(SCOUT_MOD_PATH / "dev/aws-credentials"),
        pathlib.Path(SCOUT_MOD_PATH / "data"),
        docker_poll_interval=1.0,
    )
    logging.info("Scout module started")
    s = scout.Scout(cfg, callback)
    logging.info("Submitting task to Scout module")
    taskcfg = scout.ScoutTask(
        time.strftime("scout-%Y%m%d-%H%M%S"),
    )
 
    #python3 testrun.py -t1 "tempo de execução em segundos"
    if args.task1:
        seconds = args.task1
        task_1(s, taskcfg, seconds)

    #python3 testrun.py -t2 "tempo de execução em segundos"
    if args.task2:
        seconds = args.task2
        task_2(s, taskcfg, seconds)

    #python3 testrun.py -t3 "tempo de execução em segundos"
    if args.task3:
        seconds = args.task3
        task_3(s, taskcfg, seconds)


if __name__ == "__main__":
    sys.exit(main())
