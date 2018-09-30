import hashlib

from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, UINT8, BUFFER, STRING
from playground.network.packet.fieldtypes.attributes import Optional

from labs.lab1.src.lab1_protocol.RIPPPacketType import RIPPPacketType, packet_type_mapping


class RIPPPacket(PacketType):
    DEFINITION_IDENTIFIER = "RIPP.kandarp.packet"
    DEFINITION_VERSION = "1.0"

    FIELDS = [

        ("Type", UINT8),
        ("SeqNo", UINT32({Optional: True})),
        ("AckNo", UINT32({Optional: True})),
        ("CRC", STRING),
        ("FRC", UINT32({Optional: True})),
        ("Data", BUFFER({Optional: True}))

    ]

    def calculate_checksum(self, pkt):
        return hashlib.sha1(pkt.__serialize__()).hexdigest()

    def validate(self, pkt):
        # consider adding other checks here
        tmp = pkt.CRC
        pkt.CRC = b''
        return self.calculate_checksum(pkt) == tmp

    def packet_type(self, type_no):
        if type_no in range(6):
            return packet_type_mapping[type_no]
        else:
            raise ValueError('Unknown Type {}'.format(type_no))

    def syn_packet(self, seq_no):
        syn = RIPPPacket()
        syn.Type = RIPPPacketType.SYN.value
        syn.SeqNo = seq_no
        syn.CRC = b''
        syn.CRC = syn.calculate_checksum(syn)
        return syn

    def ack_packet(self, seq_no, ack_no):
        ack = RIPPPacket()
        ack.Type = RIPPPacketType.ACK.value
        ack.SeqNo = seq_no  # TODO: verify if this is correct
        ack.AckNo = ack_no
        ack.CRC = b''
        ack.CRC = ack.calculate_checksum(ack)
        return ack

    def syn_ack_packet(self, seq_no, ack_no):
        syn_ack = RIPPPacket()
        syn_ack.Type = RIPPPacketType.SYN_ACK.value
        syn_ack.SeqNo = seq_no
        syn_ack.AckNo = ack_no
        syn_ack.CRC = b''
        syn_ack.CRC = syn_ack.calculate_checksum(syn_ack)
        return syn_ack

    def fin_packet(self, seq_no):
        fin = RIPPPacket()
        fin.Type = RIPPPacketType.FIN.value
        fin.SeqNo = seq_no
        fin.CRC = b''
        fin.CRC = fin.calculate_checksum(fin)
        return fin

    def fin_ack_packet(self, ack_no):
        fin_ack = RIPPPacket()
        fin_ack.Type = RIPPPacketType.FIN.value
        fin_ack.AckNo = ack_no
        fin_ack.CRC = b''
        fin_ack.CRC = fin_ack.calculate_checksum(fin_ack)
        return fin_ack

    def data_packet(self, seq_no, ack_no, data_content):
        data = RIPPPacket()
        data.Type = RIPPPacketType.DATA.value
        data.SeqNo = seq_no
        data.AckNo = ack_no
        data.Data = data_content
        data.CRC = b''
        data.CRC = data.calculate_checksum(data)
        return data


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

    pkt3 = RIPPPacket().syn_packet(1)
    print(pkt3.CRC)
    pkt4 = RIPPPacket().ack_packet(2, 3)
    pkt5 = RIPPPacket().syn_ack_packet(1, 2)
    pkt6 = RIPPPacket().data_packet(1, 2, b'abc')
    print(pkt6.Data, pkt6.SeqNo, pkt6.CRC)
