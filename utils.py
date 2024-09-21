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
from binascii import hexlify

class Misc():
    IP_LENGTH_BYTES = 4
    @staticmethod
    def split_ip(ip):
        return ip.split("/")
    
    @staticmethod
    def mac_to_string(mac):
        return hex(mac[0]).replace("0x", "") + ":" + \
                hex(mac[1]).replace("0x", "") + ":" + \
                hex(mac[2]).replace("0x", "") + ":" + \
                hex(mac[3]).replace("0x", "") + ":" + \
                hex(mac[4]).replace("0x", "") + ":" + \
                hex(mac[5]).replace("0x", "")
    @staticmethod
    def validate_ip_mask(network, network_bits):
        if network[0] == 10:
           return network_bits >= 8 and network_bits <= 32
        if network[0] == 192 and network[1] == 168:
            return network_bits >= 16 and network_bits <= 32
        if network[0] == 172 and (network[1] >> 4) & 31 == 1:
            return network_bits >= 12 and network_bits <= 32
        return False

    @staticmethod
    def ip_to_int(ip):
        return int(ip[0]) << 24 | \
            int(ip[1]) << 16 | \
                int(ip[2]) << 8 | \
                    int(ip[3])

    @staticmethod
    def int_to_ip_str(ip):
        buf = [0] * Misc.IP_LENGTH_BYTES
        buf[0] = str((ip >> 24) & 0xFF)
        buf[1] = str((ip >> 16) & 0xFF)
        buf[2] = str((ip >> 8) & 0xFF)
        buf[3] = str(ip & 0xFF)
        return buf

    @staticmethod
    def format_ip_str(ip):
        return str(ip[0]) + "." + str(ip[1]) + "." + str(ip[2]) + "." + str(ip[3])

    @staticmethod
    def get_list_of_addresses(network, network_bits):
        host_bits = 32 - network_bits
        num_hosts = 2 ** host_bits
        address = Misc.ip_to_int(network)
        if address & (num_hosts - 1) != 0:
            raise ValueError("Invalid network address")
        ips = []
        for i in range(1, num_hosts - 1):
            ip = address + i
            ips.append(Misc.int_to_ip_str(ip))
        return ips
