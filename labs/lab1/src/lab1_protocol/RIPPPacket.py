import hashlib

from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, BUFFER, STRING

from .RIPPPacketType import RIPPPacketType, packet_type_mapping


class RIPPPacket(PacketType):
    DEFINITION_IDENTIFIER = "RIPP.kandarp.packet"
    DEFINITION_VERSION = "1.0"

    FIELDS = [

        ("Type", STRING),
        ("SeqNo", UINT32),
        ("AckNo", UINT32),
        ("CRC", BUFFER),
        ("Data", BUFFER)

    ]

    def calculate_checksum(self, pkt):
        return hashlib.sha256(pkt.__serialize__()).digest()

    def validate(self, pkt):
        # consider adding other checks here
        tmp = pkt.CRC
        pkt.CRC = b''
        valid = self.calculate_checksum(pkt) == tmp
        pkt.CRC = tmp
        return valid

    def packet_type(self, type_no):
        if type_no in range(6):
            return packet_type_mapping[type_no]
        else:
            raise ValueError('Unknown Type {}'.format(type_no))

    def syn_packet(self, seq_no):
        syn = RIPPPacket()
        syn.Type = RIPPPacketType.SYN.value
        syn.SeqNo = seq_no
        syn.AckNo = 0
        syn.CRC = b''
        syn.Data = b''
        syn.CRC = syn.calculate_checksum(syn)
        return syn

    def ack_packet(self, seq_no=0, ack_no=0):
        ack = RIPPPacket()
        ack.Type = RIPPPacketType.ACK.value
        ack.SeqNo = seq_no
        ack.AckNo = ack_no
        ack.CRC = b''
        ack.Data = b''
        ack.CRC = ack.calculate_checksum(ack)
        return ack

    def syn_ack_packet(self, seq_no, ack_no):
        syn_ack = RIPPPacket()
        syn_ack.Type = RIPPPacketType.SYN_ACK.value
        syn_ack.SeqNo = seq_no
        syn_ack.AckNo = ack_no
        syn_ack.CRC = b''
        syn_ack.Data = b''
        syn_ack.CRC = syn_ack.calculate_checksum(syn_ack)
        return syn_ack

    def fin_packet(self, seq_no):
        fin = RIPPPacket()
        fin.Type = RIPPPacketType.FIN.value
        fin.SeqNo = seq_no
        fin.AckNo = 0
        fin.CRC = b''
        fin.Data = b''
        fin.CRC = fin.calculate_checksum(fin)
        return fin

    def fin_ack_packet(self, seq_no, ack_no):
        fin_ack = RIPPPacket()
        fin_ack.Type = RIPPPacketType.FIN.value
        fin_ack.SeqNo = seq_no  # TODO: verify if this is correct
        fin_ack.AckNo = ack_no
        fin_ack.CRC = b''
        fin_ack.Data = b''
        fin_ack.CRC = fin_ack.calculate_checksum(fin_ack)
        return fin_ack

    def data_packet(self, seq_no, data_content):
        data = RIPPPacket()
        data.Type = RIPPPacketType.DATA.value
        data.SeqNo = seq_no
        data.AckNo = 0
        data.Data = data_content
        data.CRC = b''
        data.CRC = data.calculate_checksum(data)
        return data

    def __lt__(self, other):
        return self.SeqNo < other.SeqNo

    #def __repr__(self):
    #    return super(RIPPPacket, self).__repr__() + \
    #           ". Type: " + str(self.Type) + \
    #           ". SeqNo: " + str(self.SeqNo) + \
    #           ". AckNo: " + str(self.AckNo) + \
    #           ". Data: " + str(self.Data) + \
    #           ". CRC: " + str(self.CRC)


if __name__ == "__main__":
    packet1 = RIPPPacket()
    packet1.Type = 1
    packet1.SeqNo = 1
    packet1.AckNo = 100
    packet1.CRC = b'5000'
    packet1.Data = b'Kandarp Khandwala'

    packetBytes = packet1.__serialize__()

    packet2 = PacketType.Deserialize(packetBytes)

    if packet1 == packet2:
        print("These two packets are the same! {} {}".format(packet1, packet2))
    else:
        print("Mismatched packets {} {}".format(packet1, packet2))

    pkt3 = RIPPPacket().syn_packet(1)
    pkt4 = RIPPPacket().ack_packet(2, 3)
    pkt5 = RIPPPacket().syn_ack_packet(1, 2)
    pkt6 = RIPPPacket().data_packet(1, b'abc')
    print(pkt3, pkt4, pkt5, pkt6)
