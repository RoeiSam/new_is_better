"""
author: Roei Samuel
date: 29.06.2025
purpose: Implement protocol ARP.
"""
from scapy.all import get_if_hwaddr
from struct import unpack, pack

ARP_REPLY_OPCODE = 2
ARP_REQUEST_OPCODE = 1
ARP_FORMAT = "H2sBBH6s4s6s4s"
ETHER_AND_ARP_FORMAT = "6s6s2sH2sBBH6s4s6s4s"
ARP_ETHER_TYPE = 1
IPV4_TYPE = "0800"
ARP_TYPE = "0806"
ARP_HARDWARE_SIZE = 6
ARP_PROTOCOL_SIZE = 4
ARP_REQUEST_DST_MAC = "00:00:00:00:00:00"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
MAC_SEPERATOR = ':'
IP_SEPERATOR = '.'

def arp_reply(sock, packet: bytes) -> None:
    """
    Implementation of arp reply.

    :param sock: Socket to answer with.
    :param packet: The data of the arp request.
    :return: None.
    """
    (hardware_type, protocol_type, hardware_size, protocol_size,
     opcode, src_mac, src_ip, dst_mac, dst_ip) = unpack(ARP_FORMAT, packet)
    reply = pack(ETHER_AND_ARP_FORMAT ,src_mac, dst_mac, ARP_TYPE.encode(), hardware_type, protocol_type,
                hardware_size, protocol_size, ARP_REPLY_OPCODE, dst_mac, dst_ip, src_mac, src_ip)
    sock.send(reply)


def arp_request(dst_ip: str, src_ip: str, src_mac: str, sock) -> None:
    """
    Send arp request.
    If ip is not in arp chache - this function is being called.

    :param dst_ip: Ip to ask in the request.
    :param src_ip: Soutce ip of the request.
    :param src_mac: Soutce mac of the request.
    :param sock: The socket to send the request.
    :return None
    """
    request = pack(ETHER_AND_ARP_FORMAT, BROADCAST_MAC, src_mac, ARP_TYPE, ARP_ETHER_TYPE,
                   IPV4_TYPE, ARP_HARDWARE_SIZE, ARP_PROTOCOL_SIZE, ARP_REQUEST_OPCODE, get_if_hwaddr(iface),
                   src_ip, ARP_REQUEST_DST_MAC, dst_ip)
    sock.send(request)


def add_to_arp_cache(data: bytes) -> None:
    """
    Extract mac and ip from the data of arp reply and add to arp cache.
    """
    print(data)
    (hardware_type, protocol_type, hardware_size, protocol_size,
    opcode, src_mac, src_ip, dst_mac, dst_ip) = unpack(ARP_FORMAT, data)
    if src_ip.hex(IP_SEPERATOR) not in arp_cache:
        arp_cache[src_ip.hex(IP_SEPERATOR)] = src_mac.hex(MAC_SEPERATOR)
        print(arp_cache)


def handle_arp(sock, data: bytes, dst_mac: str, iface: str) -> None:
    """
    Hnadle arp packets.
    Check if arp packet are request or reply and act as needed.

    :param sock: The socket to send packets with.
    :param data: Only tha data of tha ARP protocol.
    :dst_mac: The destination mac of the arp packet.
    :iface: The interface we are working with.
    """
    if dst_mac == BROADCAST_MAC:  # Check if packet is arp request
        arp_reply(sock, data)
    elif dst_mac == get_if_hwaddr(iface): # Check if packet is arp reply
        add_to_arp_cache(data)