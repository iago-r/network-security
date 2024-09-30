# DynMap

DynMap is an algorithm that can be used to find dynamic IP addresses from a set of observations relating an IP address to a fingerprint (X.509 certificate, SSH key, or anything else).

DynMap is introduced in the paper ["Dynamic IP Address Identification from Public Data"](https://sol.sbc.org.br/index.php/sbseg/article/view/30074). If you use DynMap in your research, please cite us.

DynMap is a general script that takes a standardized input (mapping IP to fingerprint) and can be expanded to support several sources of data. The main DynMap script is `dynmap.py`.

The minimal set of observations needed for each IP address is:

- IP address
- Port
- Domain name
- Fingerprint
- Timestamp (When the data above was collected)

Currently, the algorithm supports Shodan scans and can search IP addresses for HTTPS and SSH modules, the pre-processing step is done by the `preprocess-shodan.py` script, which takes a collection of Shodan scans and generates **.pickle** files in the format DynMap expects.

## Current features

As of now, a user can:

- Extract data from Shodan scans and run DynMap to find dynamic IP addresses
- Create new pre-processing scripts for other data sources
- Log every step of the analysis by using the `DEBUG` flag
- Save IP addresses found as **.pickle** files for later use

## Example usage

Both the pre-processing and the main script use a cache folder. The default cache folder is `cache/` and can be changed by using the `--cache-folder` or `-c` flag.

This folder is used to store extracted data from the pre-processing step as well as data needed by the **pyasn** library.

### Pre-processing

Given a directory `shodan_ips` containing several Shodan scans as **.json** or **.json.bz2** files, the pre-processing step can be done by running:

```bash
./preprocess-shodan.py path/to/shodan_ips [module]
```

Where `module` is one of `https` or `ssh`. This will generate **.pickle** files in the `cache/` folder. These files are ready to be used by the main script.

It is **imperative to use several days as input to the pre-processing step**. DynMap needs a time series to analyze fingerprint usage over time. Ideally the days should be consecutive and the minimum recommended amount (for Shodan) is a month.

This may vary depending on the data source, keep this in mind when using other data sources, you need enough data to build a good time series.

### Main script

After the pre-processing step, DynMap can be run:

```bash
./dynmap.py -s
```

By default, the script will look for compatible **.pickle** files in the `cache/` folder. The **pyasn** database is also automatically downloaded if it is not found in the cache folder.

By using the `--save-ips` or `-s` flag, the dynamic IP addresses found are saved in a **.pickle** file in the same folder where the script is run.

## General configuration

Both scripts have flags for logging, debugging and changing the cache folder. The main script has additional flags. Use the `--help` flag to see all available options.

```bash
./preprocess-shodan.py -c /path/to/another/cache -f debug.log -l DEBUG 
```

## DynMap configuration

DynMap has four parameters that can be adjusted to fine-tune the algorithm:

- `--block-size` or `-b` (default 8): The minimum size of a block of IP addresses.

- `--max-gap-size` or `-g` (default 8): The maximum number of consecutive IP addresses that can be missing from a block.

- `--entropy-smoothing-threshold` or `-t` (default 0.5): The threshold used to classify an IP address as dynamic when building sub-blocks.

- `--median-filter-window-size` or `-w` (default 5): The size of the smoothing window used to apply the median filter for each IP.

In a nutshell, the parameters `w` and `t` affect the reliability of DynMap. High values of `t` yield more restrictive sub-blocks, classifying only IPs with higher entropies. Low values of `w` reduce the transfer of inferences from an IP to its neighbors in the median filter, classifying only IPs that already have good inferences.

The parameters `b` and `g` affect the coverage of DynMap, **as they directly impact the construction of blocks**. High values of `b` result in Autonomous Systems from smaller organizations being discarded, as they do not have enough IPs in the address space to form large blocks with few gaps. High values of `g` counteract increasing the value of `b`, as they allow the construction of larger blocks while tolerating the presence of gaps, increasing the number of small Autonomous Systems found.

*DynMap will use the default values if no parameters are given.*

## Input format

DynMap expects a standardized input format. Three files are needed:

- `FPI.pickle`: a dict of unique fingerprints found per IP address
  - **Type:** `dict[str, set[str]]`
  - **Maps:** IP address -> set of fingerprints

- `IPF.pickle`: a dict of unique IP addresses found per fingerprint
  - **Type:** `dict[str, set[str]]`
  - **Maps:** fingerprint -> set of IP addresses

- `IFOT.pickle`: a dict of a timeseries for each IP address
  - **Type:** `dict[str, list[tuple[dt.datetime, str, int, str]]]`
  - **Maps:** IP address -> list of tuples, where each tuple contains (timestamp, fingerprint, port, domain). The list is sorted by timestamp, oldest to newest.

These files are generated by the pre-processing step (e.g., `preprocess-shodan.py`), you should follow the same format if you are creating a new pre-processing script.

## Output format

The output of DynMap is a dict with analysis metadata and the dynamic IP addresses found:

```python
{
    "min_block_size": int,
    "max_gap_size": int,
    "smoothing_threshold": float,
    "median_window_size": int,
    "total_input_ips": int,
    "total_output_ips": int,
    "dynamic_ips": list[str],
    "proxy_ips": list[str],
    "cluster_ips": list[str]
}
```

These are only saved if the `--save-ips` flag is used.

## Performance and Memory

Since DynMap needs a time series to analyze fingerprint usage over time, the pre-processing step requires a substantial amount of memory which scales linearly with the amount of unique IPs across scans, as well as the average amount of unique fingerprints per IP. As for the extraction process, several CPU cores are used at the same time to extract multiple files in parallel.

### Complexity

The memory requirement for both scripts is $O(NF)$, where $N$ is the number of IP addresses in the input dataset and $F$ is the average number of distinct fingerprints per IP.

The extraction script has a time complexity of $O(N)$ to process the input data. The main script has a time complexity of $O(KB^2)$ to analyze the data, where $K$ is the amount of blocks built and $B$ is the minimum block size, as it needs to compare every IP address with every other IP address in the same block.
