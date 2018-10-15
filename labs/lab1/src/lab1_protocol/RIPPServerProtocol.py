import random
from collections import OrderedDict

from playground.network.common import StackingProtocol

from labs.lab1.src.lab1_protocol.RIPPPacket import RIPPPacket
from labs.lab1.src.lab1_protocol.RIPPPacketType import RIPPPacketType, max_seq_no
from labs.lab1.src.lab1_protocol.RIPPServerTransport import RIPPServerTransport


class RIPPServerProtocol(StackingProtocol):

    def __init__(self):
        self.transport = None
        self.deserializer = None
        self.receive_window = dict()
        self.sending_window = OrderedDict()
        super(RIPPServerProtocol, self).__init__()

    # ---------- Overridden methods ---------------- #

    def connection_made(self, transport):
        self.transport = transport
        self.deserializer = RIPPPacket.Deserializer()

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)

    def data_received(self, data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if isinstance(pkt, RIPPPacket) and pkt.validate(pkt):
                if pkt.Type == RIPPPacketType.DATA.value:
                    print("Received Data {}".format(pkt))
                    self.receive_data_packet(pkt)
                elif pkt.Type == RIPPPacketType.SYN_ACK.value:
                    print("Received SYN ACK {}".format(pkt))
                    self.receive_syn_ack_packet(pkt)
                elif pkt.Type == RIPPPacketType.ACK.value:
                    print("Received ACK {}".format(pkt))
                    self.receive_ack_packet(pkt)
                elif pkt.Type == RIPPPacketType.FIN.value:
                    print("Received FIN {}".format(pkt))
                    self.receive_fin_packet(pkt)
                elif pkt.Type == RIPPPacketType.FIN_ACK.value:
                    print("Received FIN-ACK {}".format(pkt))
                    self.receive_fin_ack_packet(pkt)
                elif pkt.Type == RIPPPacketType.SYN.value:
                    print("Received SYN {}".format(pkt))
                    self.receive_syn_packet(pkt)
            else:
                self.connection_lost("---> Found error in packet {}".format(pkt))

    # ---------- Custom methods ---------------- #

    # ---------- Send Packets ---------------- #

    def send_syn_ack_packet(self, pkt):
        print("Sending SYN ACK")
        seq = random.randrange(100, max_seq_no // 100)
        syn_ack = RIPPPacket().syn_ack_packet(seq_no=seq, ack_no=pkt.SeqNo + 1)
        self.receive_window[seq] = syn_ack
        self.transport.write(syn_ack.__serialize__())
        print("SYN-ACK Sent")

    def send_syn_packet(self):
        print("Sending SYN")
        seq = random.randrange(100)
        syn = RIPPPacket().syn_packet(seq_no=seq)
        self.receive_window[seq] = syn
        self.transport.write(syn.__serialize__())
        print("SYN Sent")

    def send_ack_packet(self, syn_ack):
        print("Sending ACK")
        ack = RIPPPacket().ack_packet(seq_no=syn_ack.AckNo, ack_no=syn_ack.SeqNo + 1)
        self.transport.write(ack.__serialize__())
        print("ACK Sent")

    def send_data_ack_packet(self, pkt):
        print("Sending ACK for {}".format(pkt))
        data_ack = RIPPPacket().ack_packet(seq_no=pkt.SeqNo, ack_no=pkt.SeqNo + len(pkt.Data))
        self.transport.write(data_ack.__serialize__())
        print("ACK sent for data. Sending upstream")
        self.higherProtocol().data_received(pkt.Data)
        self.receive_window.pop(pkt.SeqNo)

    def send_fin_ack_packet(self, fin):
        print("Sending FIN-ACK")
        fin_ack = RIPPPacket().fin_ack_packet(seq_no=fin.AckNo, ack_no=fin.SeqNo + 1)
        self.transport.write(fin_ack.__serialize__())
        print("FIN-ACK Sent")

    def chunk_data_packets(self, seq_no, pkt):
        print("Chunking data packet {}".format(pkt))
        for pkt_chunk in [pkt[i:i + 1500] for i in range(0, len(pkt), 1500)]:
            self.sending_window[seq_no] = pkt_chunk
            seq_no += len(pkt_chunk)
        return seq_no

    def send_data_packets(self):
        for seq_no, data_chunk in self.sending_window.copy().items():
            data = RIPPPacket().data_packet(seq_no=seq_no, data_content=data_chunk)
            print("Sending Data down the wire {}".format(data))
            self.transport.write(data.__serialize__())
            self.sending_window.pop(seq_no)

    # ---------- Receive Packets ---------------- #

    def receive_syn_packet(self, syn):
        if syn.validate(syn):
            self.send_syn_ack_packet(syn)
        else:
            self.connection_lost("Invalid SYN Packet received from the client")

    def receive_data_packet(self, pkt):
        if pkt.validate(pkt):
            # TODO: Add SeqNo check
            print("Data {} received with len {}".format(pkt, len(pkt.Data)))
            self.receive_window[pkt.SeqNo] = pkt
            self.send_data_ack_packet(pkt)  # TODO: run in seprate thread
        else:
            self.connection_lost("Invalid Data Packet received from the client {}".format(pkt.SeqNo))

    def receive_syn_ack_packet(self, syn_ack):
        if syn_ack.validate(syn_ack) and syn_ack.AckNo in self.receive_window:
            self.receive_window.pop(syn_ack.AckNo)
            self.send_ack_packet(syn_ack)
            higher_protocol = RIPPServerTransport(self, self.transport)
            higher_protocol.start_seq(syn_ack.AckNo)
            self.higherProtocol().connection_made(higher_protocol)
            # self.transport.start_seq(syn_ack.AckNo)
        else:
            self.connection_lost("Invalid SYN ACK Packet received from the client")

    def receive_ack_packet(self, pkt):
        if pkt.validate(pkt) and pkt.AckNo - 1 in self.receive_window:
            print("Popping from window")
            self.receive_window.pop(pkt.AckNo - 1)
            higher_protocol = RIPPServerTransport(self, self.transport)
            higher_protocol.start_seq(pkt.AckNo)
            self.higherProtocol().connection_made(higher_protocol)
            # self.transport.start_seq(pkt.AckNo)
        else:
            self.connection_lost("Invalid ACK Packet received from the client")

    def receive_fin_packet(self, fin):
        if fin.validate(fin):
            # TODO: take care of the buffer here
            self.send_fin_ack_packet(fin)
        else:
            self.connection_lost("Invalid FIN Packet received from the client")

    def receive_fin_ack_packet(self, pkt):
        if pkt.validate(pkt):
            self.transport.close()
        else:
            self.connection_lost("Invalid FIN-ACK Packet received from the client")
