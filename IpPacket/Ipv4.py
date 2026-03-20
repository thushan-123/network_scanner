'''

    Version (4bits)
    Header-length (4bits)
    D-Services (8bits)
    Total-len (16bits)
    Identification (16bits)
    Flags (3bit)
    Fragment-offset (13bits)
    TTL (8bits)
    Protocol (8bits) TCP -6 UDP -17
    Checksum (16bits)
    Source-ip (32 bits)
    Destination-ip (32 bits)

'''


class Ipv4():
    def CreateIpv4Packet(
            self,
            version,
            header_length,
            d_services,
            Identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            source_ip,
            destination_ip
    ):
        pass