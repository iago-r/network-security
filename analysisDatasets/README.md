# Analysis Shodan Censys data

## Info and help

The "analysis_shodan_censys_data.py" library has useful functions for loading, parsing, and analyzing Shodan and Censys data.
 
Some useful functions can be used, for more information about the necessary parameters, just type: ```python3 analysis_shodan_censys_data.py -h```

In the file itself, there are explanations about each of the functions in addition to the parameters necessary for their use.

## Execution

When running the file ``` python3 analysis_shodan_censys_data.py <parameters>``` all the functions will be executed in sequence, depending on the type of the input directory (Shodan or Censys data).

For example, running the command ``` python3 analysis_shodan_censys_data.py --directoryShodan <shodan input directory> --directoryStoreUFMGShodanData <output folder to store UFMG data from shodan> --ipUFMG 150.164.0.0/16 --outputDirectory <folder to store the analysis results> ```, the following functions will be executed:
- filter_ufmg_shodan = This function will filter and store in "--directoryStoreUFMGShodanData" the Shodan Data related to UFMG
- probe_data_shodan_and_censys = This function will analyze the input data, collecting info about the modules on the scan, the attributes collected, and the IPs and ports verified.
- temporal_scan_ip_shodan_censys = This function will make a temporal analysis of input data, summarizing scan information collected through the days present on the input file, like IPs scanned, unique IPs verified, and repeated IPs.

About Censys data, the command ``` python3 analysis_shodan_censys_data.py --directoryCensys <censys input directory> --directoryStoreCensysShodanFormat <output folder to store Censys data parsed into Shodan format> --outputDirectory <folder to store the analysis results>  ```
will perform the same actions as mentioned before, but another function will be used:
- load_censys_in_shodan_format = This function will receive the Censys file and parse it into Shodan format, storing the output on "--directoryStoreCensysShodanFormat". This function is important so the analysis can be performed on both Shodan and Censys data.

### Important: The function to filter UFMG data from the input is not executed in Censys, because the data collected from Censys is already from UFMG, while Shodan data contains information about Brazil

## Code

About the code, the file is divided into classes, like the main class 'AnalysisShodanCensysData' that contains all the analysis functions to handle Shodan and Censys data, the class 'Shodan' contains different attributes to aggregate all elements collected on the scan, helping the process of loading the scan info into memory. Finally, the class 'FileSummary' handles the information collected during the analysis, organizing all the elements and storing the output.