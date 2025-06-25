"""
author: Roei Samuel
date: 25.06.2025
purpose: Implement TCP/IP stack.
"""
from scapy.all import conf, IFACES
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
ETHET_TYPE_END = 14
ETHER_DATA_START = 15
RECV_PACKET_LOCATION = 1
ARP_TYPE = "0806"
ARP_REPLY_ETHER_TYPE = 1
IPV4_TYPE = "0800"
ARP_REPLY_HARDWARE_SIZE = 6
ARP_REPLY_PROTOCOL_SIZE = 4
ARP_REPLY_OPCODE = 2
ARP_REQUEST_UNPACK = "H2sBBH6s4s6s4s"
ARP_REPLY_PACK = "6S6S2SH2sBBH6s4s6s4s"


def ethernet(packet: bytes) -> Union[bytes, None]:
    """
    Implement the ethernet layer.

    :param packet: The packet in raw data.
    :return: The Destination mac, source mac, type of next protocol, and the data
    of the layers above if the packet is for this computer, None if not for this computer.
    """
    mac_list = [BROADCAST_MAC, MY_MAC, FIRST_MULTICAST_MAC, SECOND_MULTICAST_MAC]
    dst_mac, src_mac, type = unpack(ETHER_UNPACK_FORMAT, packet[:ETHET_TYPE_END])
    if dst_mac.hex(MAC_SEPERATOR) not in mac_list:
        return None, None, None
    else:
        return dst_mac.hex(MAC_SEPERATOR), type.hex(), packet[ETHER_DATA_START:]


def arp_reply(sock, packet: bytes) -> None:
    """
    Implementation of arp reply.

    :param sock: Socket to answer with.
    :param packet: The data of the arp request.
    :return: The reply to the arp request.
    """
    print("arp reply")
    (hardware_type, protocol_type, hardware_size, protocol_size,
     opcode, src_mac, src_ip, dst_mac, dst_ip) = unpack(ARP_REQUEST_UNPACK, packet)
    reply = pack(ARP_REPLY_PACK ,src_mac, dst_mac, ARP_TYPE, hardware_type, protocol_type,
                hardware_size, protocol_size, ARP_REPLY_OPCODE, dst_mac, dst_ip, src_mac, src_ip)
    sock.send(reply)
    print(reply)

def main():
    IFACES.show()
    iface = IFACE
    recv = [None, None, None]

    while (not isinstance(recv[RECV_PACKET_LOCATION], bytes)):
        sock = conf.L2socket(iface=iface, promisc=True)  # Create the socket
        recv = sock.recv_raw()  # Receive data
        if (isinstance(recv[RECV_PACKET_LOCATION], bytes)):
            dst_mac, type, data = ethernet(recv[RECV_PACKET_LOCATION])
            if(type == ARP_TYPE and dst_mac == BROADCAST_MAC):
                arp_reply(sock, data)
    sock.close()



if __name__ == "__main__":
    main()
