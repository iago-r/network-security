# Censys


## Bash version:

The `download_censys.sh` script downloads Censys snapshots. When running it, a menu will be available with the following options:
 - Press 1 to list all snapshots available to download;
 - Press 2 to download the latest snapshot;
 - Press 3 to download a specific snapshot. When using this option, a new dialogue will appears to user specify a snapshot id.

When downloading a snapshot, the script will create (if not exists) a folder `./original/<snapshot_id>`. If a folder with the same name already exists, the script will skip this process.


Before run it, please define an environment variable CENSYS\_API and CENSYS\_API\_SECRET to set your permissions


## Python version:

Using this version in Python, users can download Censys data in an interactive mode, where the application list all available dumps, by using the command `python download.py --interactive`. Users can also run directly in shell by using the flag `dumps` as used in `python download.py --dumps 20240808`. All available parameters are detailed by running the command `$ python download.py --help`.