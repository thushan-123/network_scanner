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


class Ipv4():
    def CreateIpv4Packet(
            self,
            Identification,
            flags: int,
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
