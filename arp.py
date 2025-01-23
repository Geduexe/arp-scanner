from scapy.all import ARP, Ether, srp
import argparse
import psutil
import ipaddress
import socket



# Function to perform ARP scan
def arp_scan(target_network):
    network = ipaddress.IPv4Network(target_network, strict=False)
    for ip in network.hosts():
        arp_request = ARP(pdst=str(ip))
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        for sent, received in answered_list:
            print(f"IP: {received.psrc}, MAC: {received.hwsrc}")

# Function to get the interface's IP, netmask, and MAC address using psutil
def get_interface_info(interface_name):
    interfaces = psutil.net_if_addrs()
    for interface in interfaces:
        if interface.lower() == interface_name.lower():
            ip = None
            netmask = None
            mac = None
            for addr in interfaces[interface]:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    netmask = addr.netmask
                elif addr.family == psutil.AF_LINK:
                    mac = addr.address
            if ip and mac:
                return ip, netmask, mac
            else:
                print(f"Could not find the IPv4 address and/or MAC address for interface: {interface_name}")
                return None, None, None
    print(f"Interface not found: {interface_name}")
    return None, None, None

# Main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Scanner")
    parser.add_argument("-i", "--interface", dest="interface", help="Network interface name (e.g., Wi-Fi, Ethernet).")
    parser.add_argument("-t", "--target", dest="target", help="Target network range (e.g., 192.168.1.0/24).")
    args = parser.parse_args()

    if not args.interface and not args.target:
        parser.error("At least one of -i or -t is required.")

    if args.target:
        target_network = args.target
        print(f"Scanning target network: {target_network}")
        arp_scan(target_network)
    elif args.interface:
        ip, netmask, mac = get_interface_info(args.interface)
        if ip and mac:
            print(f"Interface: {args.interface}")
            print(f"IP: {ip}, MAC: {mac}")
        else:
            print("ARP scan aborted due to missing IP address or MAC address.")
            exit(1)
