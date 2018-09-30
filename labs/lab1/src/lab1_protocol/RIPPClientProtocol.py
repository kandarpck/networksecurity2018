import random
from datetime import datetime

from playground.network.common import StackingProtocol

from labs.lab1.src.lab1_protocol.RIPPPacket import RIPPPacket
from labs.lab1.src.lab1_protocol.RIPPPacketType import RIPPPacketType


class RIPPClientProtocol(StackingProtocol):

    def __init__(self):
        self.transport = None
        self.deserializer = None
        self.sliding_window = dict()
        super(RIPPClientProtocol, self).__init__()

    # ---------- Overridden methods ---------------- #

    def connection_made(self, transport):
        self.transport = transport
        self.deserializer = RIPPPacket.Deserializer()

        # Start three-way handshake
        print('Starting three-way handshake with {} at {}'.format(
            transport.get_extra_info("peername"),
            datetime.now()

        ))
        self.send_syn_packet()

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)

    def data_received(self, data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if pkt.Type == RIPPPacketType.DATA.value:
                self.receive_data(pkt)
            elif pkt.Type == RIPPPacketType.SYN_ACK.value:
                print("Received SYN ACK")
                self.receive_syn_ack_packet(pkt)
            elif pkt.Type == RIPPPacketType.ACK.value:
                self.receive_ack_packet(pkt)
            elif pkt.Type == RIPPPacketType.FIN.value:
                print("Received FIN")
                self.receive_fin_packet(pkt)
            elif pkt.Type == RIPPPacketType.FIN_ACK.value:
                self.receive_fin_ack_packet(pkt)

    # ---------- Custom methods ---------------- #

    def send_syn_packet(self):
        print("Sending SYN")
        seq = random.randrange(100)
        syn = RIPPPacket().syn_packet(seq_no=seq)
        self.sliding_window[seq] = syn
        self.transport.write(syn.__serialize__())
        print("SYN Sent")

    def send_ack_packet(self, syn_ack):
        print("Sending ACK")
        ack = RIPPPacket().ack_packet(seq_no=syn_ack.AckNo, ack_no=syn_ack.SeqNo + 1)
        self.transport.write(ack.__serialize__())
        print("ACK Sent")

    def send_fin_ack_packet(self, fin):
        print("Sending FIN-ACK")
        fin_ack = RIPPPacket().fin_ack_packet(seq_no=fin.AckNo, ack_no=fin.SeqNo + 1)
        self.transport.write(fin_ack.__serialize__())
        print("FIN-ACK Sent")

    def receive_data(self, pkt):
        pass

    def receive_syn_ack_packet(self, syn_ack):
        if syn_ack.validate(syn_ack) and syn_ack.AckNo in self.sliding_window:
            self.sliding_window.pop(syn_ack.AckNo)
            self.send_ack_packet(syn_ack)
        else:
            self.connection_lost("Invalid SYN ACK Packet received from the server")

    def receive_ack_packet(self, pkt):
        pass

    def receive_fin_packet(self, fin):
        if fin.validate(fin):
            # TODO: take care of the buffer here
            self.send_fin_ack_packet(fin)
        else:
            self.connection_lost("Invalid FIN Packet received from the server")

    def receive_fin_ack_packet(self, pkt):
        pass
