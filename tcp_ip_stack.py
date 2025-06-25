"""
author: Roei Samuel
date: 25.06.2025
purpose: Implement TCP/IP stack.
"""
import argparse
from scapy.all import conf, IFACES
from struct import unpack

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
FIRST_MULTICAST_MAC = "01:00:5e:00:00:16"
SECOND_MULTICAST_MAC = "33:33:ff:a4:73:48"
MAC_SEPERATOR = ':'
ETHER_UNPACK_FORMAT = "6s6sH"
ETHETET_HEADER_LENGTH = 14


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
    dst_mac, src_mac, type = unpack(ETHER_UNPACK_FORMAT, packet[:ETHET_TYPE_END])

    return dst_mac.hex(MAC_SEPERATOR), src_mac.hex(MAC_SEPERATOR), type.hex(), packet[ETHER_DATA_START:]


def is_our_packet(packet: bytes, iface) -> bool:
    mac_list = [BROADCAST_MAC, scapy.get_if_hwaddr(iface), FIRST_MULTICAST_MAC, SECOND_MULTICAST_MAC]
    dst_mac, src_mac, next_protocol, ether_data = parse_ether_packet(packet_data)
    return dst_mac.hex(MAC_SEPERATOR) in mac_list


def main() -> None:
    args = get_args()
    iface = args.interface

    while True:
        sock = conf.L2socket(iface=iface, promisc=True)  # Create the socket
        class_, packet_data, timestamp = sock.recv_raw()  # Receive data
        if packet_data is not None:
            if is_our_packet(packet_data, iface):
                dst_mac, src_mac, next_protocol, ether_data = parse_ether_packet(packet_data)


if __name__ == "__main__":
    main()
