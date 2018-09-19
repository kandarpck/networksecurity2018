from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT8, UINT16, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
import asyncio


class RIPPPacket(PacketType):
    DEFINITION_IDENTIFIER = "RIPP.kandarp.packet"
    DEFINITION_VERSION = "1.0"

    FIELDS = [

        ("Type", UINT8),
        ("SeqNo", UINT32({Optional: True})),
        ("AckNo", UINT32({Optional: True})),
        ("CRC", UINT16),
        ("FRC", UINT32({Optional: True})),
        ("Data", BUFFER({Optional: True}))

    ]


class MyProtocol(asyncio.Protocol):
    def __init__(self):
        self.transport = None
        self.deserializer = None

    def connection_made(self, transport):
        self.transport = transport
        self.deserializer = PacketType.Deserializer()

    def data_received(self, data):
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            print(pkt)

    def connection_lost(self, exc):
        self.transport = None


if __name__ == "__main__":
    test_packet = RIPPPacket()
    test_packet.Type = 1
    test_packet.SeqNo = 1
    test_packet.AckNo = 100
    test_packet.CRC = 5000
    test_packet.Data = b'Kandarp sends his regards'

    packetBytes = test_packet.__serialize__()

    packet2 = PacketType.Deserialize(packetBytes)

    if test_packet == packet2:
        print("These two packets are the same!")
