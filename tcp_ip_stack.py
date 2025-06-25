"""
author: Roei Samuel
date: 25.06.2025
purpose: Implement TCP/IP stack.
"""
import argparse
from scapy.all import conf, IFACES, get_if_hwaddr
from struct import unpack, pack
from typing import Union

IFACE = "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter"
MY_MAC = "f4:6a:dd:6e:a0:97"
MY_IP = "192.168.1.16"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
FIRST_MULTICAST_MAC = "01:00:5e:00:00:16"
SECOND_MULTICAST_MAC = "33:33:ff:a4:73:48"
MAC_SEPERATOR = ':'
ETHER_UNPACK_FORMAT = "6s6s2s"
ETHETET_HEADER_LENGTH = 14
RECV_PACKET_LOCATION = 1
ARP_TYPE = "0806"
ARP_REPLY_ETHER_TYPE = 1
IPV4_TYPE = "0800"
ARP_REPLY_HARDWARE_SIZE = 6
ARP_REPLY_PROTOCOL_SIZE = 4
ARP_REPLY_OPCODE = 2
ARP_REQUEST_UNPACK = "H2sBBH6s4s6s4s"
ARP_REPLY_PACK = "6s6s2sH2sBBH6s4s6s4s"


def get_args() -> str:
    """
    Get arguments from command line.

    :return: Interface to work with.
    """
    parser: ArgumentParser = argparse.ArgumentParser(description='Implement TCP/IP stack.')
    parser.add_argument('interface', type=str,
                        help="the interface to work with")

    return parser.parse_args()


def handle_ethernet(packet: bytes) -> bytes:
    """
    Implement the ethernet layer.

    :param packet: The packet in raw data.
    :return: Detination mac, source mac, type of next protocol and the next layers.
    """
    dst_mac, src_mac, type = unpack(ETHER_UNPACK_FORMAT, packet[:ETHETET_HEADER_LENGTH])

    return dst_mac.hex(MAC_SEPERATOR), src_mac.hex(MAC_SEPERATOR), type.hex(), packet[ETHETET_HEADER_LENGTH:]


def is_our_packet(packet: bytes, iface) -> bool:
    """
    Check if the packet was sent to us.

    :param packet: Packet to check.
    :param iface: Interface to check for.
    :return: True is was sent to us, false otherwise.
    """
    mac_list = [BROADCAST_MAC, get_if_hwaddr(iface), FIRST_MULTICAST_MAC, SECOND_MULTICAST_MAC]
    dst_mac, src_mac, ether_type = unpack(ETHER_UNPACK_FORMAT, packet[:ETHETET_HEADER_LENGTH])
    if dst_mac.hex(MAC_SEPERATOR) in mac_list:
        return True
    return False


def arp_reply(sock, packet: bytes) -> None:
    """
    Implementation of arp reply.

    :param sock: Socket to answer with.
    :param packet: The data of the arp request.
    :return: The reply to the arp request.
    """
    (hardware_type, protocol_type, hardware_size, protocol_size,
     opcode, src_mac, src_ip, dst_mac, dst_ip) = unpack(ARP_REQUEST_UNPACK, packet)
    reply = pack(ARP_REPLY_PACK ,src_mac, dst_mac, ARP_TYPE.encode(), hardware_type, protocol_type,
                hardware_size, protocol_size, ARP_REPLY_OPCODE, dst_mac, dst_ip, src_mac, src_ip)
    sock.send(reply)

def main():
    # IFACES.show()
    args = get_args()
    iface = args.interface
    # print(iface)

    while True:
        sock = conf.L2socket(iface=iface, promisc=True)  # Create the socket
        recv = sock.recv_raw()  # Receive data
        packet = recv[RECV_PACKET_LOCATION]
        if isinstance(packet, bytes):
            if is_our_packet(packet, iface):
                dst_mac, src_mac, next_protocol, ether_data = handle_ethernet(packet)
                if(next_protocol == ARP_TYPE and dst_mac == BROADCAST_MAC):
                    arp_reply(sock, ether_data)
    sock.close()



if __name__ == "__main__":
    main()
