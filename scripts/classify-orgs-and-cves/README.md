# CVE and organization classification

These scripts are used to classify organizations and CVE vulnerabilities into selected categories.

The resulting classification is a normalized vector of probabilities that can be used as a feature for XGBoost training.

This step is necessary to simplify the interaction between XGBoost and the vulnerabilities being prioritized by the model.

Instead of analyzing the webpages and CVEs directly, which is innefective and time consuming, XGBoost can use the resulting vector from these scripts as a feature, simplifying the overall process.

## Requirements

Both scripts use pre-trained [zero-shot classifier](https://huggingface.co/tasks/zero-shot-classification) models from HuggingFace.

The organization classifier also uses [EasyNMT](https://github.com/UKPLab/EasyNMT), a pre-trained translator model.

All models are downloaded automatically in the first run.

To begin, install all basic requirements by running:

```bash
pip install -r requirements.txt
```

This will install all basic dependencies, except for the AI modules. Both transformers and easynmt use PyTorch as a backend.

The installation of PyTorch varies among operating systems and hardware (e.g. if you have CUDA support or not). It is highly recommended to install the CUDA version, as it provides a significant performance uplift.

Follow the recommended installation instructions for your configuration: [Installing PyTorch locally](https://pytorch.org/get-started/locally/).

*After installing a compatible version of PyTorch for your system*, install the last dependencies by running:

```bash
pip install transformers
pip install -U easynmt
```

If you want to customize your install, feel free to follow installation instructions for transformers: [Transformers Installation](https://huggingface.co/docs/transformers/en/installation) and easynmt: [EasyNMT Installation](https://github.com/UKPLab/EasyNMT).

## **Classifying webpages**

As of now, it is possible to classify the contents of a webpage into the following categories:

- healthcare
- government
- store
- research
- education
- bank
- security
- military
- cloud computing
- internet service provider

This is done by running **classify-orgs.py** over a collection of Shodan scans.

The resulting classification can be saved as a **.pickle** file or a **.json** file.

In order to get a good result, multiple classification tries are made using different variables from the scan:

- First try with the 50% most common sentences in the webpage.
- If the score is too low, try with the webpage title and organization.
- If the score is still too low, try with the hostnames.
- Fallback to the original result if no extra data is available or if the score could not be improved.

This may lead to some scans taking longer to classify than others, but nothing that severely impacts performance.

## Input format

This script takes a collection of Shodan scans as **.json** (JSON) or **.json.bz2** (BZ2) as input and expects the following formats:

Each BZ2 file is one-line-per-object, where each object is a JSON string:

```txt
{object1}
{object2}
{object3}
...
```

Each JSON file is a list-with-objects, where each object is already native JSON:

```txt
[
  {object1},
  {object2},
  {object3},
  ...
]
```

BZ2 files are more efficient, as they are loaded into memory on demand and can hold thousands of Shodan scans, whereas JSON files are loaded fully into memory.

*As such, we recommend using small JSON files for experiments only.*

## Example usage

Given a directory `shodan_ips` containing **.json** or **.json.bz2** files as described above, the classification can be done by running:

```bash
./classify_orgs.py path/to/shodan_ips output_file
```

A log of execution will be printed on screen, use the `--help` flag to see all available options.

By default, the output will be a **.pickle** file, to get a **.json** output, add the `-j` flag at the end.

A sample log of execution can be seen below:

```txt
12/20/2024 04:28:52 PM - INFO: Using device: cuda
12/20/2024 04:28:52 PM - INFO: Log level: INFO
12/20/2024 04:28:52 PM - INFO: Output file: output_file.pickle
12/20/2024 04:28:52 PM - INFO: Loading model... this may take a while on the first run
12/20/2024 04:28:55 PM - INFO: Progress 1 / 534932
12/20/2024 04:29:41 PM - INFO: Progress 1001 / 534932

...

12/20/2024 07:20:33 PM - INFO: Output file saved to output_file.pickle
```

## Output format

The output of the org classification is a dict where:

- Keys are Shodan IDs of the scans. Originally present in the scans as **_shodan.id**.
- Values are dicts with the output vector for the respective classification.

The Shodan IDs are used for correlation when importing data to XGBoost.

```python
{
    "4d3a75ca-69a7-4616-97e0-75e101b1ccaf": {
        "education": 0.8712608814239502,
        "research": 0.0719912052154541,
        "government": 0.011826400645077229,
        "cloud computing": 0.011755581945180893,
        "security": 0.00847696978598833,
        "military": 0.007243294734507799,
        "internet service provider": 0.005284429062157869,
        "healthcare": 0.005233842879533768,
        "store": 0.003908179234713316,
        "bank": 0.0030192292761057615
    },
    ...
}
```

## **Classifying CVEs**

As of now, it is possible to classify a CVE into the following categories:

- remote code execution
- denial of service
- cross site scripting
- information disclosure
- sql injection
- privilege escalation
- buffer overflow
- cross site request forgery

Additionally, the configuration required to exploit the vulnerability is classified into three categories:

- default (i.e. active in default configuration)
- specific (i.e. active only in specific configurations)
- unknown (i.e. no mention of which configuration is affected)

This is done by running **classify-cves.py** over a zipfile with CVEs from Mitre.

The resulting classification can be saved as a **.pickle** file or a **.json** file.

## Input format

The classifier needs a summary and other details associated with a CVE in order to perform the classification.

Currently, this script relies on Mitre as a supplier of this data in the [CVE JSON](https://www.cve.org/AllResources/CveServices#CveRecordFormat) format.

The file can be downloaded here: [CVE Downloads](https://www.cve.org/Downloads). Click on the *main.zip* link, a file named *cvelistV5-main.zip* should begin downloading.

*Note that this process may change should Mitre update this format.*

## Example usage

Given a file `cvelistV5-main.zip` downloaded from Mitre as detailed above, the classification can be done by running:

```bash
./classify_cves.py path/to/cvelistV5-main.zip output_file
```

A log of execution will be printed on screen, use the `--help` flag to see all available options.

By default, the output will be a **.pickle** file, to get a **.json** output, add the `-j` flag at the end.

A sample log of execution can be seen below:

```txt
12/20/2024 04:28:52 PM - INFO: Using device: cuda
12/20/2024 04:28:52 PM - INFO: Log level: INFO
12/20/2024 04:28:52 PM - INFO: Output file: output_file_cves.pickle
12/20/2024 04:28:52 PM - INFO: Loading model... this may take a while on the first run
12/20/2024 04:28:55 PM - INFO: Progress 1 / 275089
12/20/2024 04:29:41 PM - INFO: Progress 1001 / 275089

...

12/20/2024 07:20:33 PM - INFO: Output file saved to output_file_cves.pickle
```

## Output format

The output of the org classification is a dict where:

- Keys are CVE IDs.
- Values are tuples with two dicts:
  - Output vector for the respective *vulnerability* classification.
  - Output vector for the respective *configuration* classification.

```python
{
    "CVE-2024-9999": {
        "vulnerability_label2score": {
            "remote code execution": 0.4048096835613251,
            "cross site request forgery": 0.37249937653541565,
            "privilege escalation": 0.07831587642431259,
            "cross site scripting": 0.053536590188741684,
            "information disclosure": 0.034364815801382065,
            "buffer overflow": 0.02017531730234623,
            "sql injection": 0.018226372078061104,
            "denial of service": 0.01807202585041523
        },
        "configuration_label2score": {
            "unknown": 0.813221275806427,
            "specific": 0.14339271187782288,
            "default": 0.04338601976633072
        }
    },
    ...
}
```

## Performance

Both scripts will run each classification sequentially, i.e. classify one scan or CVE, store the results and then classify the next one. As such, using the CUDA version of PyTorch significantly improves performance and is recommended.

Performance is limited by GPU CUDA cores or threads when using a CPU backend.

### Complexity

The memory and time requirements for both scripts is $O(N)$, where $N$ is the number of Shodan scans to process or the number of CVEs to process.
