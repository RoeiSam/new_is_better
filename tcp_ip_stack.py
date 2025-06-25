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
RECV_PACKET_LOCATION = 1


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
    dst_mac, src_mac, type = unpack(ETHER_UNPACK_FORMAT, packet[:ETHET_TYPE_END])

    return dst_mac.hex(MAC_SEPERATOR), src_mac.hex(MAC_SEPERATOR), type.hex(), packet[ETHER_DATA_START:]


def is_our_packet(packet: bytes, iface) -> bool:
    """
    Check if the packet was sent to us.

    :param packet: Packet to check.
    :param iface: Interface to check for.
    :return: True is was sent to us, false otherwise.
    """
    mac_list = [BROADCAST_MAC, scapy.get_if_hwaddr(iface), FIRST_MULTICAST_MAC, SECOND_MULTICAST_MAC]
    dst_mac, src_mac, ether_type = unpack(ETHER_UNPACK_FORMAT, packet[:ETHETET_HEADER_LENGTH])
    if dst_mac.hex(MAC_SEPERATOR) in mac_list:
        return True
    return False


def main():
    IFACES.show()
    args = get_args()
    iface = args.interface()
    recv = [None, None, None]

    while True:
        sock = conf.L2socket(iface=iface, promisc=True)  # Create the socket
        recv = sock.recv_raw()  # Receive data
        packet = recv[RECV_PACKET_LOCATION]
        if isinstance(packet, bytes):
            if is_our_packet(packet, iface):
                dst_mac, src_mac, next_protocol, ether_data = handle_ethernet(packet)



if __name__ == "__main__":
    main()
