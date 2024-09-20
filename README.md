# ARP scan utility

Scans the network for IP addresses and prints the result in human readable format

# Usage

```
$ python3 arp-scan.py --source [source IP address] --source-mac [source MAC address] --interface [send using the interface] --destination [destination IP address or network address in VLSM format] --timeout [timeout in seconds]
```

Example:

```
$ python3 arp-scan.py --source 192.168.0.10 --source-mac 7f:23:45:1d:62:2a --interface eth0 --destination 192.168.0.0/20 --timeout 3
```

Example output:

```

```