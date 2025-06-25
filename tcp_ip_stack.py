"""
author: Roei Samuel
date: 25.06.2025
purpose: Implement TCP/IP stack.
"""
import scapy
from scapy.all import conf, IFACES
from struct import unpack
from typing import Union

IFACE = "Software Loopback Interface 1"
MY_MAC = ""
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
MAC_SEPERATOR = ':'
ETHER_UNPACK_FORMAT = "6s6sH"
ETHET_TYPE_END = 14
ETHER_DATA_START = 15


def ethernet(packet: bytes) -> Union[bytes, None]:
    """
    Implement the ethernet layer.

    :param packet: The packet in raw data.
    :return: The third layer and above if the packet is for this computer, None if not.
    """
    mac_list = [BROADCAST_MAC]
    dst_mac, src_mac, ether_type = unpack(ETHER_UNPACK_FORMAT, packet[:ETHET_TYPE_END])
    print(dst_mac.hex(MAC_SEPERATOR))
    if dst_mac.hex(MAC_SEPERATOR) not in mac_list:
        return None
    else:
        return packet[ETHER_DATA_START:]



def main():
    IFACES.show()
    scapy.interfaces.show_interfaces()
    iface = IFACE
    recv = [2, "hello"]

    while(str(type(recv[1])) != "<class 'bytes'>"):
        sock = conf.L2socket(iface=iface, promisc=False)  # Create the socket
        recv = sock.recv_raw()  # Receive data
        if (str(type(recv[1])) == "<class 'bytes'>"):
            ethernet(recv[1])
            print(recv[1])



if __name__ == "__main__":
    main()
