"""
author: Roei Samuel
date: 25.06.2025
purpose: Implement TCP/IP stack.
"""
from scapy.all import conf, IFACES
from struct import unpack
from typing import Union

IFACE = "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter"
MY_MAC = "f4:6a:dd:6e:a0:97"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
FIRST_MULTICAST_MAC = "01:00:5e:00:00:16"
SECOND_MULTICAST_MAC = "33:33:ff:a4:73:48"
MAC_SEPERATOR = ':'
ETHER_UNPACK_FORMAT = "6s6sH"
ETHETET_HEADER_LENGTH = 14
RECV_PACKET_LOCATION = 1


def ethernet(packet: bytes) -> Union[bytes, None]:
    """
    Implement the ethernet layer.

    :param packet: The packet in raw data.
    :return: The third layer and above if the packet is for this computer, None if not.
    """
    mac_list = [BROADCAST_MAC, MY_MAC, FIRST_MULTICAST_MAC, SECOND_MULTICAST_MAC]
    dst_mac, src_mac, ether_type = unpack(ETHER_UNPACK_FORMAT, packet[:ETHETET_HEADER_LENGTH])
    if dst_mac.hex(MAC_SEPERATOR) not in mac_list:
        return None

    return packet[ETHETET_HEADER_LENGTH + 1:]

"""
def ethernet(packet: bytes) -> Union[bytes, None]:
    
    Implement the ethernet layer.

    :param packet: The packet in raw data.
    :return: The Destination mac, source mac, type of next protocol, and the data
    of the layers above if the packet is for this computer, None if not for this computer.
    
    mac_list = [BROADCAST_MAC, MY_MAC, FIRST_MULTICAST_MAC, SECOND_MULTICAST_MAC]
    dst_mac, src_mac, type = unpack(ETHER_UNPACK_FORMAT, packet[:ETHET_TYPE_END])
    if dst_mac.hex(MAC_SEPERATOR) not in mac_list:
        return None, None, None
    else:
        return dst_mac.hex(MAC_SEPERATOR), type.hex(), packet[ETHER_DATA_START:]
"""
def is_our_packet(packet: bytes) -> bool:
    """
    Check if the packet was sent to us.

    :return: True is was sent to us, false otherwise.
    """
    mac_list = [BROADCAST_MAC, MY_MAC, FIRST_MULTICAST_MAC, SECOND_MULTICAST_MAC]
    if dst_mac.hex(MAC_SEPERATOR) in mac_list:
        return True
    return False


def main():
    IFACES.show()
    iface = IFACE
    recv = [None, None, None]

    while True:
        sock = conf.L2socket(iface=iface, promisc=True)  # Create the socket
        recv = sock.recv_raw()  # Receive data
        if isinstance(recv[RECV_PACKET_LOCATION], bytes):
            ethernet(recv[RECV_PACKET_LOCATION])



if __name__ == "__main__":
    main()
