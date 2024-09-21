#!/usr/bin/python3

# Copyright (C) 2024 strangebit
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

__author__ = "Dmitriy Kuptsov"
__copyright__ = "Copyright 2024, strangebit"
__license__ = "GPL"
__version__ = "0.0.1b"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@strangebit.io"
__status__ = "development"

# Import the needed libraries
# RE library
import re
# Sockets
import socket
import select
# Timing
import time
# Timing 
from time import time, sleep
# Network stuff
import socket
import packets
import argparse
# Utils 
from utils import Misc
# Hex
from binascii import unhexlify, hexlify

parser = argparse.ArgumentParser(
                    prog='arp-scan',
                    description='Scans the local network for available IP addresses')

parser.add_argument("--source", dest="source", required=True, help="Source IP address to use")
parser.add_argument("--source-mac", dest="sourcemac", required=True, help="Source MAC address to use")
parser.add_argument("--interface", dest="interface", required=True, help="Outbound interface name as appeared in ifconfig")
parser.add_argument("--destination", dest="destination", required=True, help="Destination IP address or whole subnetwork to scan")
parser.add_argument("--timeout", dest="timeout", required=False, default=2, help="Timeout to wait for the reply before the process decides to drop the communication")

args = parser.parse_args()

args.timeout = int(args.timeout)
network, mask = Misc.split_ip(args.destination)
if int(mask) >32 or int(mask) < 0:
    print("Invalid mask was provided")
    exit(-1)
oc1, oc2, oc3, oc4 = network.split(".")
network = [int(oc1), int(oc2), int(oc3), int(oc4)]
mask = int(mask)
if mask < 32:
    Misc.validate_ip_mask(network, mask)
    ips = Misc.get_list_of_addresses(network, mask)
else:
    ips = [network]

ETH_P_ALL = 3
ether_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL));
ether_socket.bind((args.interface, 0))

sourcemac = args.sourcemac.split(":")
for i in range(0, len(sourcemac)):
    sourcemac[i] = int.from_bytes(unhexlify(sourcemac[i]), byteorder="big")
source = args.source.split(".")
for i in range(0, len(source)):
    source[i] = int(source[i])

for ip in ips:
    arp = packets.ArpPacket()
    arp.set_hardware_type(packets.ETH_HARDWARE_TYPE)
    arp.set_protocol_type(packets.ETH_PROTOCOL_TYPE)
    arp.set_hw_address_length(packets.ETH_HW_ADDRESS_LENGTH)
    arp.set_protocol_address_length(packets.ETH_PROTO_ADDRESS_LENGTH)
    arp.set_operation_type(packets.ARP_REQUEST_TYPE)
    arp.set_sender_hw_address(sourcemac)
    arp.set_sender_protocol_address(source)

    destination = ip

    for i in range(0, len(destination)):
        destination[i] = int(destination[i])

    arp.set_target_protocol_address(destination)
    eth_frame = packets.EthernetFrame()
    eth_frame.set_destination(packets.ETH_BROADCAST_MAC_ADDRESS)
    eth_frame.set_source(sourcemac)
    eth_frame.set_length(0x0806)
    eth_frame.set_payload(arp.get_buffer())
    ether_socket.send(bytearray(eth_frame.get_buffer()))

    start = time()
    while True:
        ready = select.select([ether_socket], [], [], args.timeout)
        if ready[0]:
            buf = ether_socket.recv(1522)
            o = []
            for b in buf:
                o.append(int(b))
            if o[packets.ETH_LENGTH_OFFSET] == 0x8 and o[packets.ETH_LENGTH_OFFSET + 1] == 0x6:                   
                eth_frame = packets.EthernetFrame(o)
                arp = packets.ArpPacket(eth_frame.get_payload())
                if eth_frame.get_length() == 0x0806 and arp.get_operation_type() == packets.ARP_REPLY_TYPE:
                    print("Got ARP reply: %s %s" % (Misc.format_ip_str(ip), Misc.mac_to_string(arp.get_target_hw_address())))
                    break
            if time() - start > args.timeout:
                print("Timeout elapsed")
                break
        else:
            print("Socket timeout occured")

    sleep(0.5)
