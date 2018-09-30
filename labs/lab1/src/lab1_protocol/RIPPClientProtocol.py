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
        print("Sending SYN")
        self.send_syn_packet()
        print("SYN Sent")

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
                self.receive_fin_packet(pkt)
            elif pkt.Type == RIPPPacketType.FIN_ACK.value:
                self.receive_fin_ack_packet(pkt)

    # ---------- Custom methods ---------------- #

    def send_syn_packet(self):
        seq = random.randrange(100)
        syn = RIPPPacket().syn_packet(seq_no=seq)
        self.sliding_window[seq] = syn
        self.transport.write(syn.__serialize__())

    def receive_data(self, pkt):
        pass

    def receive_syn_ack_packet(self, pkt):
        if pkt.validate(pkt) and pkt.AckNo in self.sliding_window:
            self.sliding_window.pop(pkt.AckNo)
            self.send_ack_packet()
        else:
            self.connection_lost("Invalid SYN ACK Packet received from the server")

    def receive_ack_packet(self, pkt):
        pass

    def receive_fin_packet(self, pkt):
        pass

    def receive_fin_ack_packet(self, pkt):
        pass
