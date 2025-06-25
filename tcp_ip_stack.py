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
ETHET_TYPE_END = 14
ETHER_DATA_START = 15
RECV_PACKET_LOCATION = 1


def ethernet(packet: bytes) -> Union[bytes, None]:
    """
    Implement the ethernet layer.

    :param packet: The packet in raw data.
    :return: The third layer and above if the packet is for this computer, None if not.
    """
    mac_list = [BROADCAST_MAC, MY_MAC, FIRST_MULTICAST_MAC, SECOND_MULTICAST_MAC]
    dst_mac, src_mac, ether_type = unpack(ETHER_UNPACK_FORMAT, packet[:ETHET_TYPE_END])
    if dst_mac.hex(MAC_SEPERATOR) not in mac_list:
        return None
    else:
        return packet[ETHER_DATA_START:]



def main():
    IFACES.show()
    iface = IFACE
    recv = [None, None, None]

    # while(str(type(recv[RECV_PACKET_LOCATION])) != "<class 'bytes'>"):
    while (not isinstance(recv[RECV_PACKET_LOCATION], bytes)):
        sock = conf.L2socket(iface=iface, promisc=True)  # Create the socket
        recv = sock.recv_raw()  # Receive data
        if (isinstance(recv[RECV_PACKET_LOCATION], bytes)):
            ethernet(recv[RECV_PACKET_LOCATION])



if __name__ == "__main__":
    main()
