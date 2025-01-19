from scapy.all import ARP, Ether, srp
import argparse

# Function to scan the network
def arp_scan(target_ip):
    arp_request = ARP(pdst=target_ip) 
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    for sent, received in answered_list:
        print(f"IP: {received.psrc} MAC: {received.hwsrc}")

# Main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Scanner")
    parser.add_argument("-t", "--target", dest="target", help="IP address of the target")
    args = parser.parse_args()

    arp_scan(args.target)