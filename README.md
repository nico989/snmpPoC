# SNMP PoC
SNMP Bash Script to discover valid community strings, dump basic information, check for write permission and check for RCE.

# Usage
How to run it:
```
$ ./snmp.sh --help
Usage: snmp.sh [--help] --ip IP 

SNMP Bash Script to discover valid community strings, dump basic information, check for write permission and check for RCE.

Arguments:
--help                   Show this help message and exit
--ip IP                  Target IP to test

$ ./snmp.sh --ip <TARGET IP>
```
The results are stored in a file called `snmp_log.txt` in same folder of the script by default.

# Credits
- Abusing Linux SNMP for RCE: https://mogwailabs.de/en/blog/2019/10/abusing-linux-snmp-for-rce/
- Hacktricks: https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp/snmp-rce
