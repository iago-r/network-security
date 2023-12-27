# How to Install Libraries MIB's and Run SNMP Module

The SNMP management protocol has several modules that can be useful for our project, among them is the snmpwalk module. With it, it is possible to read information from devices on the network using protocols in versions 1 and 2 (authentication is required to read information from systems with version 3 protocol). Through this information, we can identify various details about the device. Here's an example of some information:

```
SNMPv2-MIB::sysDescr.0 = RouterOS CCR1009-7G-1C-1S+
SNMPv2-MIB::sysObjectID.0 = SNMPv2-SMI::enterprises.14988.1
SNMPv2-MIB::sysUpTime.0 = 531108500
SNMPv2-MIB::sysContact.0 = 
SNMPv2-MIB::sysName.0 = CGNAT - BORDA FIBERNET
SNMPv2-MIB::sysLocation.0 = 
SNMPv2-MIB::sysServices.0 = 78
SNMPv2-SMI::mib-2.2.1.0 = 17
SNMPv2-SMI::mib-2.2.2.1.1.1 = 1
SNMPv2-SMI::mib-2.2.2.1.1.2 = 2
SNMPv2-SMI::mib-2.2.2.1.1.3 = 3
```
After conducting some scans, it is noticeable that some information is in a less readable format, like the example line:
```
SNMPv2-SMI::mib-2.2.2.1.1.1 = 1
```
The line above can be translated as IF-MIB::ifIndex.1, which means a unique value for each interface. This translation can be done manually through the Cisco website:
```
https://snmp.cloudapps.cisco.com/Support/SNMP/do/BrowseOID.do?local=en
```
However, for our analysis, it will be necessary to automate the process and consultation of this MIB.

## What is a MIB
A Management Information Base (MIB) is a database of information, consisting of a tree of objects identified by object numbers (OIDs). These objects represent specific aspects of managed devices, such as configurations, performance, and status. There are various types of MIBs, including proprietary ones, but we are using the standard MIB of the module.

![MIB Image](/img/mib-tree-diagram.png)

This is the standard diagram of the MIB we are using.

In addition to reading information, the created module also performs translation to make it easier to collect data. To perform this translation, some components are required.

## snmptranslate
SNMP translate is a module that accesses MIB libraries on the computer, and through the information in this library, it is possible to convert from numeric to text format, making it easier to read. However, to access these libraries, it is necessary to download them, which will be copied to the path ```/var/lib/mibs/ietf``` on the system (Linux).

## Installation of MIBs
The installation of libraries is straightforward; you only need to use the command:

```sudo apt-get install snmp-mibs-downloader```

To download the MIB downloader manager and then use the command:
```download-mibs```
This command will download all available MIBs for conversion. As it covers various standards, the **snmp-mibs-downloader** can cover a large part of them during the download.

## Conversion Process
The conversion process is also straightforward. Since it is a module, it has some additional information, but if you need to translate only one OID, the command will be:
```snmptranslate -Ta OID```
For example:
```snmptranslate -Ta SNMPv2-SMI::mib-2.2.2.1.1.1```
To:
```IF-MIB::ifIndex.1```

The ```-Ta``` parameter is used to return the OID in its simplest form, only its title. There are other parameters that can be useful and can be found on the website:

```
https://www.mkssoftware.com/docs/man1/snmptranslate.1.asp
```

## Module Details
The module is structured with the following files:
  - ```snmp-get.py```: This file is built to retrieve information from Censys, specifically designed for this type of file. In the case of tests, a Censys database with only IPs that have the SNMP port (161) open for reading was used. However, not all IPs return information; some of them time out. The module is executed with:
  ```
  python3 snmp-get.py data.json
  ```

  - ```snmpwalk.py``` and ```translate.py```: The snmpwalk and translate modules perform the scan and translate information, respectively. Both are executed in the call of the scan module. The translate module is organized so that if a value is incorrect and cannot be translated, it will be ignored.

  - ```scan.py```: The scan module aggregates both modules and executes the scan using threads. When dealing with multiple IPs, the thread execution was created so that we can launch 20 scanners at once, and each time a scan is finished, another is queued so that 20 scanners are always running simultaneously.