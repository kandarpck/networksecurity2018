from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT8, UINT16, BUFFER
from playground.network.packet.fieldtypes.attributes import Optional
from labs.lab1.src.lab1_protocol.RIPPPacketType import RIPPPacketType, packet_type_mapping


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

    def packet_type(self, type_no):
        if type_no in range(6):
            return packet_type_mapping.get(type_no)
        else:
            raise ValueError('Unknown Type {}'.format(type_no))

    def syn_packet(self, seq_no):
        pass

    def ack_packet(self, ack_no):
        pass

    def syn_ack_packet(self, seq_no, ack_no):
        pass

    def fin_packet(self, seq_no):
        pass

    def fin_ack_packet(self, ack_no):
        pass

    def data_packet(self, seq_no, ack_no, data):
        pass


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
        print("These two packets are the same! {} {}".format(packet1, packet2))
    else:
        print("Mismatched packets {} {}".format(packet1, packet2))
