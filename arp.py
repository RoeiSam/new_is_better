"""
author: Roei Samuel
date: 29.06.2025
purpose: Implement protocol ARP.
"""
from enum import Enum
from ethernet import encapsule_data
from scapy.all import get_if_hwaddr
from struct import unpack, pack

class ArpOpcode(Enum):
    ARP_REQUEST_OPCODE = 1
    ARP_REPLY_OPCODE = 2
class ProtocolType(Enum):
    IPV4_TYPE = b"0800"
    ARP_TYPE = b"0806"
ARP_FORMAT = "H2sBBH6s4s6s4s"
ETHER_FORMAT = "6s6s2s"
ETHER_AND_ARP_FORMAT = ETHER_FORMAT + ARP_FORMAT
ARP_ETHER_TYPE = 1
ARP_ETHER_HARDWARE_SIZE = 6
ARP_IP_PROTOCOL_SIZE = 4
ARP_REQUEST_DST_MAC = "00:00:00:00:00:00"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
MAC_SEPERATOR = ':'

arp_cache = {}


def arp_reply(sock, packet: bytes) -> bytes:
    """
    Pack and return an ARP reply.

    :param sock: Socket to answer with.
    :param packet: The data of the ARP protocol in the ARP request.
    :return: Tha ARP protocol reply data.
    """
    (hardware_type, protocol_type, hardware_size, protocol_size,
     opcode, src_mac, src_ip, dst_mac, dst_ip) = unpack(ARP_FORMAT, packet)
    reply_data = pack(ARP_FORMAT ,hardware_type, protocol_type, hardware_size, protocol_size,
                 ArpOpcode.ARP_REPLY_OPCODE.value, dst_mac, dst_ip, src_mac, src_ip)
    return reply_data, dst_mac, src_mac


def arp_request(dst_ip: str, src_ip: str, src_mac: str, sock) -> None:
    """
    Pack and return ARP request.

    :param dst_ip: IP to ask in the request.
    :param src_ip: Source IP of the request.
    :param src_mac: Source mac of the request.
    :param sock: The socket to send the request.
    :return Tha ARP protocol request data.
    """
    request_data = pack(ARP_FORMAT, ARP_ETHER_TYPE, ProtocolType.IPV4_TYPE.value, ARP_ETHER_HARDWARE_SIZE,
                   ARP_IP_PROTOCOL_SIZE, ArpOpcode.ARP_REQUEST_OPCODE, get_if_hwaddr(iface),src_ip, ARP_REQUEST_DST_MAC, dst_ip)
    return request_data


def add_to_arp_cache(src_ip, src_mac) -> None:
    """
    Extract mac and IP from the data of ARP reply and add to ARP cache.
    """
    if src_ip not in arp_cache:
        arp_cache[src_ip] = src_mac


def send_ether_arp(data: bytes, dst_mac, src_mac, sock) -> None:
    """
    Send ARP packet encapsulated in ETHER protocol.
    """
    packet = encapsule_data(data, len(data), dst_mac, src_mac, ProtocolType.ARP_TYPE.value)
    sock.send(packet)


def handle_arp(sock, data: bytes, dst_mac: str, iface: str) -> None:
    """
    Hnadle ARP packets.
    Check if ARP packet are request or reply and act as needed.

    :param sock: The socket to send packets with.
    :param data: Only tha data of tha ARP protocol.
    :dst_mac: The destination mac of the ARP packet.
    :iface: The interface we are working with.
    """
    (hardware_type, protocol_type, hardware_size, protocol_size,
     opcode, src_mac, src_ip, dst_mac, dst_ip) = unpack(ARP_FORMAT, data)
    if opcode == ArpOpcode.ARP_REQUEST_OPCODE:  # Check if packet is arp request
        reply_data, dst_mac, src_mac = arp_reply(sock, data)
        send_ether_arp(reply_data, dst_mac, src_mac)
    elif opcode == ArpOpcode.ARP_REPLY_OPCODE: # Check if packet is arp reply
        add_to_arp_cache(src_ip, src_mac)