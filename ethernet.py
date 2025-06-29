"""
author: Roei Samuel
date: 29.06.2025
purpose: Implement protocol ETHERNET in second layer.
"""
from scapy.all import get_if_hwaddr
from struct import unpack, pack

ETHER_FORMAT = "6s6s2s"
ETHETET_HEADER_LENGTH = 14
FIRST_MULTICAST_MAC = "01:00:5e:00:00:16"
SECOND_MULTICAST_MAC = "33:33:ff:a4:73:48"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
MAC_SEPERATOR = ':'


def parse_ether_packet(packet: bytes) -> bytes:
    """
    Extract the ethernet layer data.

    :param packet: The packet in raw data.
    :return: Detination mac, source mac, type of next protocol and the next layers.
    """
    dst_mac, src_mac, type = unpack(ETHER_FORMAT, packet[:ETHETET_HEADER_LENGTH])

    return dst_mac.hex(MAC_SEPERATOR), src_mac.hex(MAC_SEPERATOR), type.hex(), packet[ETHETET_HEADER_LENGTH:]



def is_our_packet(packet: bytes, iface) -> bool:
    """
    Check if the packet was sent to us.

    :param packet: Packet to check.
    :param iface: Interface to check for.
    :return: True is was sent to us, false otherwise.
    """
    mac_list = [BROADCAST_MAC, get_if_hwaddr(iface), FIRST_MULTICAST_MAC, SECOND_MULTICAST_MAC]
    dst_mac, src_mac, ether_type = unpack(ETHER_FORMAT, packet[:ETHETET_HEADER_LENGTH])
    return dst_mac.hex(MAC_SEPERATOR) in mac_list
