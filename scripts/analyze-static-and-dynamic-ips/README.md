# Find Static and Dynamic IP addresses

This python script can be used to find static and dynamic IP addresses from a collection of Shodan scans.

Run `python3 analyze_ips.py -h` to print a help menu with more detailed information.

This script supports only Shodan scans and can search IP addresses for modules https and ssh.

## The user can

- Add more modules by modifying the `initSupportedModules()` function
- Log every step of the analysis by using the `DEBUG` flag
- Save IP addresses found as .pickle files for later use

## Example usage

Given a directory `ufmg_ips` containing several Shodan scans as .json files

Run `python3 analyze_ips.py ufmg_ips/ https -f=output.log`

The output will be similar to:

12/24/2023 12:28:38 AM - INFO: Selected module: https \
12/24/2023 12:28:38 AM - INFO: Loading scans from BR.20231008.json \
. \
. \
. \
12/24/2023 12:29:49 AM - INFO: Filtering IP addresses \
12/24/2023 12:29:49 AM - INFO: Found 635 static IP addresses \
12/24/2023 12:29:49 AM - INFO: Found 0 dynamic IP addresses \
12/24/2023 12:29:49 AM - INFO: Static IP addresses ratio 100.000000%

A `DEBUG` output for the same command will be similar to:

12/26/2023 05:41:05 PM - INFO: Selected module: https \
12/26/2023 05:41:05 PM - INFO: Loading scans from BR.20231008.json \
. \
. \
. \
12/26/2023 05:41:23 PM - DEBUG: Rule 1 - IP address 150.164.99.158 flagged as static \
12/26/2023 05:41:23 PM - DEBUG: Rule 1 - IP address 150.164.32.35 flagged as static \
12/26/2023 05:41:23 PM - DEBUG: Rule 2 - IP address 150.164.23.222 flagged as possible dynamic \
. \
. \
. \
12/26/2023 05:41:23 PM - DEBUG: Rule 3 - Time series for IP address 150.164.23.222 \
12/26/2023 05:41:23 PM - DEBUG: Rule 3 - T: 2023-10-04 09:28:54.443172 P: 443 F: 173e68206155fc60efd87deb0bb0500a06ff37705b4bf2cdee6beaab316a7774 \
12/26/2023 05:41:23 PM - DEBUG: Rule 3 - T: 2023-10-06 14:37:53.204124 P: 10000 F: d1497d50f07e0bf6ff5683bf3291b2df46ac0e0c50bb96644217038f16bad9d7 \
12/26/2023 05:41:23 PM - DEBUG: Rule 3 - T: 2023-10-07 08:54:42.519940 P: 443 F: 173e68206155fc60efd87deb0bb0500a06ff37705b4bf2cdee6beaab316a7774 \
12/26/2023 05:41:23 PM - DEBUG: Rule 3 - T: 2023-10-12 23:26:27.281603 P: 10000 F: d1497d50f07e0bf6ff5683bf3291b2df46ac0e0c50bb96644217038f16bad9d7 \
. \
. \
. \
12/26/2023 05:41:23 PM - DEBUG: Rule 3 - IP address 150.164.23.222 flagged as static \
12/24/2023 12:29:49 AM - INFO: Found 635 static IP addresses \
12/24/2023 12:29:49 AM - INFO: Found 0 dynamic IP addresses \
12/24/2023 12:29:49 AM - INFO: Static IP addresses ratio 100.000000%

## Performance and Memory

This script requires a substantial amount of memory which scales linearly with the amount of unique IPs across scans, as well as the average amount of unique fingerprints per IP.

The memory usage while reading files scales linearly with the size of the biggest .json file, since the entire file is loaded into memory so that pydantic can check its type.

From some small tests using the `memory_profiler` module, the memory usage can be described as follows:

- The memory usage when analyzing data is on average 0.5 to 0.9 times the amount of unique IPs
- The first step of reading the files to get data is the one with max memory usage, around 1.6 times more memory than the data analysis step

For instance, for 635 unique IP addresses, the analysis step peaked at 505 MB, while the 'read scans from file' step peaked at 880 MB.
