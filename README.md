# arp-scanner
Arp scanner made in python using scapy

## Usage Guide:

### Scanning a Target Network:
Use the `-t` or `--target` flag to specify the network range:

**`python arp.py -t 192.168.1.0/24`**

This will scan all hosts in the specified subnet and list their IP and MAC addresses.

### Getting Interface Details:
Use the `-i` or `--interface` flag to specify the network interface:

**`python arp.py -i Wi-Fi`**

For Linux:

**`python arp.py wlan0`**

This will display the IP, netmask, and MAC address of the specified interface.

### Combining Options:
The script will prioritize scanning if the `-t` option is provided. Use the `-i` flag to retrieve interface details when needed.


