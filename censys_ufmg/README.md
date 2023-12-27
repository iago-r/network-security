# Censys UFMG

The `censys_ufmg.sh` script downloads the scan conducted on the UFMG network. To configure the APIID and APIKEY on the server under my user, it was necessary to create a virtual environment for the installation of the Censys Python module. The following command is required to activate the virtual environment:

```
source Censys/env-censys/bin/activate
```

After that, the following command should be used for possible APIID and APIKEY configurations:

```
censys config
```

The script is running as a cronjob:

```
MAILTO=sacramento.15@hotmail.com
0 8 * * 3 sh censys.sh
```

This cronjob performs the download, compresses the data into a .bz2 format, and moves it to the directory ```/home/storage/censys_UFMG/``` on the server. After successfully completing the download, an email is sent to inform the cron status.

