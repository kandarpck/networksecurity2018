from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT8, UINT16, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional


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


if __name__ == "__main__":
    packet1 = RIPPPacket()
    packet1.Type = 1
    packet1.SeqNo = 1
    packet1.AckNo = 100
    packet1.CRC = 5000
    packet1.Data = b'Kandarp Khandwala'

    packetBytes = packet1.__serialize__()

    packet2 = PacketType.Deserialize(packetBytes)

    if packet1 == packet2:
        print("These two packets are the same!")
    else:
        print("Mismatched packets {} {}".format(packet1, packet2))
