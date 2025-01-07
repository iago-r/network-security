#!/usr/bin/env python3

import argparse
import json
import logging
import pickle
import zipfile
from dataclasses import dataclass
from dataclasses_json import dataclass_json
from typing import Any

import torch
from transformers import Pipeline, pipeline


# Return type of classifications
@dataclass_json
@dataclass
class CVEClassification:
    vulnerability_label2score: dict[str, float]
    configuration_label2score: dict[str, float]


# Candidate labels
VULN_LABELS: list[str] = [
    "remote code execution",
    "denial of service",
    "cross site scripting",
    "information disclosure",
    "sql injection",
    "privilege escalation",
    "buffer overflow",
    "cross site request forgery",
]

CONFIG_LABELS: list[str] = [
    "active in the default configuration.",
    "active only in specific configurations.",
    "active in an unknown configuration, there is no mention of which configuration is affected.",
]


def initParser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Classifies CVEs from Mitre into vulnerability categories using a zero-shot classifier. \
        The result is a vector of probabilities for each category that can be used as a feature for the XGBoost model."
    )

    parser.add_argument(
        "cveFile",
        metavar="cve-file",
        type=str,
        help="path to a file with CVEs to be classified, this file is a .zip downloaded directly from Mitre (e.g. cvelistV5-main.zip)",
    )

    parser.add_argument(
        "outFile",
        metavar="output-file",
        type=str,
        default="cve-output",
        help="path to the output file. The default format is .pickle, use a -j flag to get a .json file instead",
    )

    parser.add_argument(
        "-j",
        "--out-json",
        dest="jsonOutput",
        action="store_true",
        default=False,
        help="If enabled, the output file will be a .json file instead of .pickle. (default: %(default)s)",
    )

    parser.add_argument(
        "-f",
        "--logfile",
        type=str,
        dest="logfile",
        action="store",
        default=None,
        help="file to store log outputs. If not specified, logs will be printed on screen",
    )

    parser.add_argument(
        "-l",
        "--loglevel",
        type=str,
        dest="loglevel",
        metavar="LOGLEVEL",
        action="store",
        choices=["DEBUG", "INFO", "WARN", "ERROR", "FATAL"],
        default="INFO",
        help="log level. Available options: DEBUG, INFO, WARN, ERROR, FATAL (default: %(default)s)",
    )

    return parser


def simplifyConfigLabels(labels: list[str]) -> list[str]:
    """
    Simplifies the configuration labels to make them more readable.

    Parameters
    ----------
    `labels`: list of configuration labels.

    Returns
    -------
    `simplified`: list of simplified configuration labels.
    """

    simplified: list[str] = []

    for label in labels:
        if "active in the default configuration" in label:
            simplified.append("default")

        if "active only in specific configurations" in label:
            simplified.append("specific")

        if "active in an unknown configuration" in label:
            simplified.append("unknown")

    return simplified


def classifyCveVulnerability(classifier: Pipeline, vulnSummary: str) -> dict[str, Any]:
    """
    Classifies a CVE into a vulnerability category.

    The classification is not binary and produces a vector of probabilities.

    Parameters
    ----------
    `classifier`: zero-shot classifier model.
    `vulnSummary`: CVE summary to be classified, in English.

    Returns
    -------
    `result`: dictionary with the classification result.
    """

    # Summary is already in EN, we don't need to translate

    # Get sequence to classify and add some context
    sequence: str = f"{vulnSummary}"
    hypothesis: str = "This summary is from a {} vulnerability."

    result: dict = classifier(
        sequences=sequence,
        candidate_labels=VULN_LABELS,
        hypothesis_template=hypothesis,
        multi_label=False,
    )

    return result


def classifyCveConfiguration(classifier: Pipeline, vulnSummary: str) -> dict[str, Any]:
    """
    Classifies a CVE into a configuration category.

    That is, if the vulnerability is active in the default configuration of a software, or not.

    The classification is not binary and produces a vector of probabilities.

    Parameters
    ----------
    `classifier`: zero-shot classifier model.
    `vulnSummary`: CVE summary to be classified, in English.

    Returns
    -------
    `result`: dictionary with the classification result.
    """

    # Summary is already in EN, we don't need to translate

    # Get sequence to classify and add some context
    sequence: str = f"{vulnSummary}"
    hypothesis: str = "This vulnerability is {}."

    result: dict = classifier(
        sequences=sequence,
        candidate_labels=CONFIG_LABELS,
        hypothesis_template=hypothesis,
        multi_label=False,
    )

    return result


def processCvesFromMitre(
    filepath: str, classifier: Pipeline
) -> dict[str, CVEClassification]:
    """
    Process all CVEs from a Mitre zip file and classify them using a zero-shot classifier.

    The CVEs are classified into vulnerability categories and further classified into configuration categories.

    Parameters
    ----------
    `filepath`: path to the zip file containing the CVEs.
    `classifier`: zero-shot classifier model.

    Returns
    -------
    `result`: dictionary with the classification result for each CVE.
    """

    seenCves: dict[str, tuple[str, dict[str, float]]] = dict()

    with zipfile.ZipFile(filepath, "r") as file:
        # NOTE: we will reverse the list to process the latest CVEs first.
        # This way we process only the updated versions of the CVEs.

        # The zip file contains a folder with all the CVEs as JSON files
        cveFilename: list[str] = file.namelist()
        cveFilename.reverse()

        for idx, cveFile in enumerate(cveFilename):
            if idx % 1000 == 0:
                logging.info(f"Progress {idx + 1} / {len(cveFilename)}")

            # There are some files that are not JSON, they do not contain CVEs
            if not cveFile.endswith(".json"):
                continue

            with file.open(cveFile) as f:
                data: dict[str, Any] = json.loads(f.read())

                try:
                    state: str = data["cveMetadata"]["state"]

                    if state == "REJECTED":
                        continue

                    summary: str = data["containers"]["cna"]["descriptions"][0]["value"]
                    id: str = data["cveMetadata"]["cveId"]
                except (KeyError, TypeError):
                    continue

                if id in seenCves:
                    continue

                resultVuln: dict[str, Any] = classifyCveVulnerability(
                    classifier, summary
                )
                resultConfig: dict[str, Any] = classifyCveConfiguration(
                    classifier, summary
                )

                # Store dataclass
                seenCves[id] = CVEClassification(
                    vulnerability_label2score={
                        l: s for l, s in zip(resultVuln["labels"], resultVuln["scores"])
                    },
                    configuration_label2score={
                        l: s
                        for l, s in zip(
                            simplifyConfigLabels(resultConfig["labels"]),
                            resultConfig["scores"],
                        )
                    },
                )

                # Immediate result with debug
                logging.debug(f"{id}: {summary} -> {seenCves[id]}")
                logging.debug("")  # Readability

    return seenCves


def genOutputFile(
    filepath: str, cvesResult: dict[str, CVEClassification], jsonOutput: bool
) -> None:
    """
    Generates an output file of the desired format.

    Parameters
    ----------
    `filepath`: output file path.
    `cvesResult`: dictionary with the results of the classification.
    `jsonOutput`: if True, the output file will be a .json file, otherwise it will be a .pickle file.
    """

    if jsonOutput:
        with open(filepath, "w") as f:
            cvesResultDict: dict[str, Any] = {
                k: v.to_dict() for k, v in cvesResult.items()
            }

            json.dump(cvesResultDict, f, indent=4)
    else:
        pickle.dump(cvesResult, open(filepath, "wb"))

    logging.info(f"Output file saved to {filepath}")


if __name__ == "__main__":
    # Get args
    parser = initParser()
    args = parser.parse_args()

    # Auto enable log file if log level is DEBUG
    if args.loglevel == "DEBUG" and args.logfile == None:
        args.logfile = f"classify_cves_debug.log"
        print(
            f"A log file is required for log level DEBUG. Logs will be written to '{args.logfile}'"
        )

    # Set up log
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s: %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S %p",
        level=getattr(logging, args.loglevel),
        filename=args.logfile,
        encoding="utf-8",
    )

    device: str = "cuda" if torch.cuda.is_available() else "cpu"
    args.outFile += ".json" if args.jsonOutput else ".pickle"

    # Run summary
    logging.info(f"Using device: {device}")
    logging.info(f"Log level: {args.loglevel}")
    logging.info(f"Output file: {args.outFile}")

    # Run
    logging.info("Loading model... this may take a while on the first run")

    classifier: Pipeline = pipeline(
        "zero-shot-classification",
        model="MoritzLaurer/deberta-v3-large-zeroshot-v2.0",
        batch_size=16,
        device=device,
        fp16=True,
    )

    cvesResult: dict = processCvesFromMitre(args.cveFile, classifier)

    genOutputFile(args.outFile, cvesResult, args.jsonOutput)
