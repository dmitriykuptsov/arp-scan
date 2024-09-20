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

ETH_DESTINATION_MAC_ADDRESS_LENGTH = 0x6
ETH_DESTINATION_MAC_ADDRESS_OFFSET = 0x0
ETH_SOURCE_MAC_ADDRESS_LENGTH = 0x6
ETH_SOURCE_MAC_ADDRESS_OFFSET = 0x6
ETH_LENGTH_LENGTH = 0x2
ETH_LENGTH_OFFSET = 0xC

ETH_BROADCAST_MAC_ADDRESS = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
ETH_HARDWARE_TYPE = 0x1
ETH_PROTOCOL_TYPE = 0x0800
ETH_HW_ADDRESS_LENGTH = 0x6
ETH_PROTO_ADDRESS_LENGTH = 0x4

ETH_HEADER_LENGTH = 0xE

class EthernetFrame():
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = [0] * (ETH_DESTINATION_MAC_ADDRESS_LENGTH + \
                                 ETH_SOURCE_MAC_ADDRESS_LENGTH + \
                                    ETH_LENGTH_LENGTH)
        else:
            self.buffer = buffer

    def set_source(self, src):
        self.buffer[ETH_SOURCE_MAC_ADDRESS_OFFSET:ETH_SOURCE_MAC_ADDRESS_OFFSET+ETH_SOURCE_MAC_ADDRESS_LENGTH] = src
    
    def get_source(self):
        return self.buffer[ETH_SOURCE_MAC_ADDRESS_OFFSET:ETH_SOURCE_MAC_ADDRESS_OFFSET+ETH_SOURCE_MAC_ADDRESS_LENGTH]
    
    def set_destination(self, dst):
        self.buffer[ETH_DESTINATION_MAC_ADDRESS_OFFSET:ETH_DESTINATION_MAC_ADDRESS_OFFSET+ETH_DESTINATION_MAC_ADDRESS_LENGTH] = dst
    
    def get_destination(self):
        self.buffer[ETH_DESTINATION_MAC_ADDRESS_OFFSET:ETH_DESTINATION_MAC_ADDRESS_OFFSET+ETH_DESTINATION_MAC_ADDRESS_LENGTH]

    def set_length(self, length):
        self.buffer[ETH_LENGTH_OFFSET] = (length >> 8) & 0xFF
        self.buffer[ETH_LENGTH_OFFSET + 1] = (length & 0xFF)

    def get_length(self):
        length = (self.buffer[ETH_LENGTH_OFFSET] << 8) & 0xFF00
        length |= (self.buffer[ETH_LENGTH_OFFSET + 1] & 0xFF)
        return length
    
    def set_payload(self, payload):
        self.buffer += payload
    
    def get_payload(self):
        return self.buffer[ETH_HEADER_LENGTH:]

    def get_buffer(self):
        return self.buffer

ARP_PACKET_LENGTH = 0x1C
ARP_REQUEST_TYPE = 1
ARP_REPLY_TYPE = 2
ARP_HADRDWARE_TYPE_OFFSET = 0x0
ARP_HADRDWARE_TYPE_LENGTH = 0x2
ARP_PROTOCOL_TYPE_OFFSET = 0x2
ARP_PROTOCOL_TYPE_LENGTH = 0x2
ARP_HARDWARE_ADDRESS_LENGTH_OFFSET = 0x4
ARP_HARDWARE_ADDRESS_LENGTH_LENGTH = 0x1
ARP_PROTOCOL_ADDRESS_LENGTH_OFFSET = 0x5
ARP_PROTOCOL_ADDRESS_LENGTH_LENGTH = 0x1
ARP_OPERATION_TYPE_OFFSET = 0x6
ARP_OPERATION_TYPE_LENGTH = 0x2
ARP_SENDER_HW_ADDRESS_OFFSET = 0x8
ARP_SENDER_HW_ADDRESS_LENGTH = 0x6
ARP_SENDER_PROTOCOL_ADDRESS_OFFSET = 0xE
ARP_SENDER_PROTOCOL_ADDRESS_LENGTH = 0x4
ARP_TARGET_HW_ADDRESS_OFFSET = 0x14
ARP_TARGET_HW_ADDRESS_LENGTH = 0x6
ARP_TARGET_PROTOCOL_ADDRESS_OFFSET = 0x18
ARP_TARGET_PROTOCOL_ADDRESS_LENGTH = 0x4

class ArpPacket():
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = [0] * ARP_PACKET_LENGTH
        else:
            self.buffer = buffer
        
    def set_hardware_type(self, type):
        self.buffer[ARP_HADRDWARE_TYPE_OFFSET] = (type >> 0x8) & 0xFF
        self.buffer[ARP_HADRDWARE_TYPE_OFFSET + 1] = (type & 0xFF)
    
    def get_hardware_type(self):
        type = (self.buffer[ARP_HADRDWARE_TYPE_OFFSET] << 0x8)
        type |= self.buffer[ARP_HADRDWARE_TYPE_OFFSET + 1]
        return type
    
    def set_protocol_type(self, type):
        self.buffer[ARP_PROTOCOL_TYPE_OFFSET] = (type >> 0x8) & 0xFF
        self.buffer[ARP_PROTOCOL_TYPE_OFFSET + 1] = (type & 0xFF)
    
    def get_protocol_type(self):
        type = (self.buffer[ARP_PROTOCOL_TYPE_OFFSET] << 0x8)
        type |= self.buffer[ARP_PROTOCOL_TYPE_OFFSET + 1]
        return type
    
    def set_hw_address_length(self, length):
        self.buffer[ARP_HARDWARE_ADDRESS_LENGTH_OFFSET] = length

    def get_hw_address_length(self, length):
        return self.buffer[ARP_HARDWARE_ADDRESS_LENGTH_OFFSET]
    
    def set_protocol_address_length(self, length):
        self.buffer[ARP_PROTOCOL_ADDRESS_LENGTH_OFFSET] = length

    def get_protocol_address_length(self, length):
        return self.buffer[ARP_PROTOCOL_ADDRESS_LENGTH_OFFSET]    

    def set_operation_type(self, type):
        self.buffer[ARP_OPERATION_TYPE_OFFSET] = (type >> 0x8) & 0xFF
        self.buffer[ARP_OPERATION_TYPE_OFFSET + 1] = (type & 0xFF)
    
    def get_operation_type(self):
        type = (self.buffer[ARP_OPERATION_TYPE_OFFSET] << 0x8) & 0xFF00
        type |= self.buffer[ARP_OPERATION_TYPE_OFFSET + 1] & 0xFF
        return type

    def set_sender_hw_address(self, address):
        self.buffer[ARP_SENDER_HW_ADDRESS_OFFSET:ARP_SENDER_HW_ADDRESS_OFFSET + ARP_SENDER_HW_ADDRESS_LENGTH] = address

    def get_sender_hw_address(self):
        return self.buffer[ARP_SENDER_HW_ADDRESS_OFFSET:ARP_SENDER_HW_ADDRESS_OFFSET + ARP_SENDER_HW_ADDRESS_LENGTH]
    
    def set_sender_protocol_address(self, address):
        self.buffer[ARP_SENDER_PROTOCOL_ADDRESS_OFFSET:ARP_SENDER_PROTOCOL_ADDRESS_OFFSET + ARP_SENDER_PROTOCOL_ADDRESS_LENGTH] = address

    def get_sender_protocol_address(self):
        return self.buffer[ARP_SENDER_PROTOCOL_ADDRESS_OFFSET:ARP_SENDER_PROTOCOL_ADDRESS_OFFSET + ARP_SENDER_PROTOCOL_ADDRESS_LENGTH]
    
    def set_target_hw_address(self, address):
        self.buffer[ARP_SENDER_HW_ADDRESS_OFFSET:ARP_SENDER_HW_ADDRESS_OFFSET + ARP_SENDER_HW_ADDRESS_LENGTH] = address

    def get_target_hw_address(self):
        return self.buffer[ARP_SENDER_HW_ADDRESS_OFFSET:ARP_SENDER_HW_ADDRESS_OFFSET + ARP_SENDER_HW_ADDRESS_LENGTH]
    
    def set_target_protocol_address(self, address):
        self.buffer[ARP_TARGET_PROTOCOL_ADDRESS_OFFSET:ARP_TARGET_PROTOCOL_ADDRESS_OFFSET + ARP_TARGET_PROTOCOL_ADDRESS_LENGTH] = address

    def get_target_protocol_address(self):
        return self.buffer[ARP_TARGET_PROTOCOL_ADDRESS_OFFSET:ARP_TARGET_PROTOCOL_ADDRESS_OFFSET + ARP_TARGET_PROTOCOL_ADDRESS_LENGTH]
    
    def get_buffer(self):
        return self.buffer
