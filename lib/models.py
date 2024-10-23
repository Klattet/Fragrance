from dataclasses import dataclass, astuple
from typing import Optional, Self

__all__ = "Frame", "IPHeader", "IPPacket"

@dataclass(slots = True)
class Frame:
    preamble: bytes # 7 bytes
    start_of_frame_delimiter: bytes # 1 byte
    destination_mac: bytes # 6 bytes
    source_mac: bytes # 6 bytes
    type: bytes # 2 bytes
    data: bytes #
    frame_check_sequence: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        if not (72 <= len(data) <= 1526):
            raise ValueError("Can't recognise bytes as a Frame.")

        return cls(
            data[:8],
            data[8:9],
            data[9:16],
            data[16:23],
            data[23:25],
            data[25:-4],
            data[-4:]
        )

    @staticmethod
    def _mac(address: bytes) -> str:
        return address.hex(sep = ":", bytes_per_sep = 1).upper()

    def __repr__(self) -> str:
        return (
            f"{'Destination MAC':<16}: {self._mac(self.destination_mac)}\n"
            f"{'Source MAC':<16}: {self._mac(self.source_mac)}\n"
            f"{'Type':<16}: {self.type.hex().upper()}"
        )



@dataclass(slots = True)
class IPHeader:
    version: int
    internet_header_length: int
    differentiated_services_code_point: int
    explicit_congestion_notification: int
    total_length: int
    identification: int
    flags: str
    fragment_offset: int
    time_to_live: int
    protocol: int
    header_checksum: int
    source_address: str
    destination_address: str
    options: Optional[bytes] = None

    def __repr__(self) -> str:
        return (
            "Version: {}\n"
            "Header Length: {}\n"
            "Differentiated Services Code Point: {}\n"
            "Explicit Congestion Notification: {}\n"
            "Total Length: {}\n"
            "Identification: {}\n"
            "Flags: {}\n"
            "Fragment Offset: {}\n"
            "Time To Live: {}\n"
            "Protocol: {}\n"
            "Header Checksum: {}\n"
            "Source Address: {}\n"
            "Destination Address: {}\n"
            "Options: {}"
        ).format(*astuple(self))

class IPPacket:

    __slots__ = "bytes", "binary", "header", "data"

    def __init__(self, packet_bytes: bytes) -> None:
        self.bytes: bytes = packet_bytes
        self.binary: str = ''.join(f'{b:08b}' for b in packet_bytes)

        if not 20 <= len(packet_bytes) <= 65565:
            raise ValueError(f"IP header must between 20 and 65565 bytes.\nGot {len(packet_bytes)} bytes.")

        self.error_check_header()

        self.header: IPHeader = self.decode_header()

        if 5 < self.header.internet_header_length:
            self.header.options = self.bytes[20:self.header.internet_header_length * 4]
            self.data = self.bytes[self.header.internet_header_length * 4:]
        else:
            self.data = self.bytes[20:]

    def error_check_header(self) -> None:
        version = int(self.binary[0:4], 2)
        if version != 4:
            raise ValueError(f"Invalid version. Must be 4 for IP.\nGot {version}.")

        internet_header_length = int(self.binary[4:8], 2)
        if internet_header_length < 5:
            raise ValueError(f"Invalid header length. Must be 5 or more.\nGot {internet_header_length}.")

        ## CHECKSUM
        #checksum = int.from_bytes(self.bytes[10:12], "big")
        #header_sum = 0
        #for i in range(0, 20, 2):
        #    header_sum += int.from_bytes(self.bytes[i:i+2], "big")
        #    if 65535 < header_sum:
        #        header_sum -= 65534
        #if ~header_sum != checksum:
        #    raise ValueError(f"Header checksum does not match.\nGot {~header_sum}\nExpected {checksum}.")

    def decode_header(self) -> IPHeader:
        return IPHeader(
            int(self.binary[0:4], 2),
            int(self.binary[4:8], 2),
            int(self.binary[8:14], 2),
            int(self.binary[14:16], 2),
            int(self.binary[16:32], 2),
            int(self.binary[32:48], 2),
            self.binary[48:51],
            int(self.binary[51:64], 2),
            int(self.binary[64:72], 2),
            int(self.binary[72:80], 2),
            int(self.binary[80:96], 2),
            ".".join(str(int.from_bytes(self.bytes[i:i+1], "big")) for i in range(12, 16)),
            ".".join(str(int.from_bytes(self.bytes[i:i+1], "big")) for i in range(16, 20))
        )

    def __repr__(self) -> str:
        return (
            "HEADER:\n{}\n"
            "DATA:\n{}"
        ).format(self.header, self.data)
