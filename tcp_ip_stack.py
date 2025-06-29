"""
author: Roei Samuel
date: 25.06.2025
purpose: Implement TCP/IP stack.
"""
import argparse
from arp import arp_reply, arp_request, add_to_arp_cache, handle_arp
from ethernet import parse_ether_packet, is_our_packet
from scapy.all import conf, IFACES

ARP_TYPE = "0806"


def get_args() -> str:
    """
    Get arguments from command line.

    :return: Interface to work with.
    """
    parser: ArgumentParser = argparse.ArgumentParser(description='Implement TCP/IP stack.')
    parser.add_argument('interface', type=str,
                        help="the interface to work with")

    return parser.parse_args()


def main():
    args = get_args()
    iface = args.interface

    while True:
        sock = conf.L2socket(iface=iface, promisc=True)  # Create the socket
        class_, packet_data, timestamp = sock.recv_raw()  # Receive data
        if packet_data is not None:
            if is_our_packet(packet_data, iface):
                dst_mac, src_mac, next_protocol, ether_data = parse_ether_packet(packet_data)
                if next_protocol == ARP_TYPE: # Check if packet is arp
                    handle_arp(sock, ether_data, dst_mac, iface)
    sock.close()



if __name__ == "__main__":
    main()
