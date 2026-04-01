'''

    Version (4bits)
    Header-length (4bits)
    D-Services (8bits)
    Total-len (16bits)
    Identification (16bits)
    Flags (3bit)
    Fragment-offset (13bits)
    TTL (8bits)
    Protocol (8bits) TCP -6 UDP -17 Icmp -1
    Checksum (16bits)
    Source-ip (32 bits)
    Destination-ip (32 bits)

'''
import re
import struct

class Ipv4():
    def checksum(self,data):
        if len(data)%2 :
            data = data + b'\x00'
        s = sum(
            struct.unpack("!%dH" % (len(data) // 2), data)
        )
        s = (s >>16) + (s & 0xffff)
        s = s+ s>>16
        return  ~s & 0xffff

    def CreateIpv4Packet(
            self,
            Identification,
            flags: str,
            fragment_offset,
            ttl :int,
            protocol,
            source_ip,
            destination_ip
    ):
        version = 0x04
        d_service = 0x00
        if protocol not in [1,6,17]:
            raise ValueError("only ICMP-> 1 , TCP->6, UDP->17")
        protocol = hex(protocol)
        if ttl > 255:
            raise ValueError("exceed MAX Hop Limit - Max ttl is 255")
        ttl = hex(ttl)

        pattern = r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\." \
                  r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\." \
                  r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\." \
                  r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"

        if not (re.fullmatch(pattern, source_ip)):
            raise ValueError("incorrect source Ip")
        if not (re.fullmatch(pattern, destination_ip)):
            raise ValueError("incorrect destination ip")