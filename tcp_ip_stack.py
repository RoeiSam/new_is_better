"""
author: Roei Samuel
date: 25.06.2025
purpose: Implement TCP/IP stack.
"""
import argparse
from scapy.all import conf, IFACES, get_if_hwaddr, get_if_addr
from struct import unpack, pack

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
FIRST_MULTICAST_MAC = "01:00:5e:00:00:16"
SECOND_MULTICAST_MAC = "33:33:ff:a4:73:48"
MAC_SEPERATOR = ':'
ETHER_UNPACK_FORMAT = "6s6s2s"
ETHETET_HEADER_LENGTH = 14
ARP_TYPE = "0806"
ARP_REPLY_OPCODE = 2
ARP_REQUEST_OPCODE = 1
ARP_FORMAT = "H2sBBH6s4s6s4s"
ETHER_AND_ARP_FORMAT = "6s6s2sH2sBBH6s4s6s4s"
ARP_ETHER_TYPE = 1
IPV4_TYPE = "0800"
ARP_HARDWARE_SIZE = 6
ARP_PROTOCOL_SIZE = 4
ARP_REQUEST_DST_MAC = "00:00:00:00:00:00"


def get_args() -> str:
    """
    Get arguments from command line.

    :return: Interface to work with.
    """
    parser: ArgumentParser = argparse.ArgumentParser(description='Implement TCP/IP stack.')
    parser.add_argument('interface', type=str,
                        help="the interface to work with")

    return parser.parse_args()


def parse_ether_packet(packet: bytes) -> bytes:
    """
    Extract the ethernet layer data.

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
    return dst_mac.hex(MAC_SEPERATOR) in mac_list


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
        arp_reply(sock, ether_data)
    else if dst_mac == get_if_hwaddr(iface): # Check if packet is arp reply
        pass
        #add_to_arp_cache()


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
