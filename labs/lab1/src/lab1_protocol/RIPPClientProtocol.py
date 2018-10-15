import random
from collections import OrderedDict
from datetime import datetime

from playground.network.common import StackingProtocol

from labs.lab1.src.lab1_protocol.RIPPClientTransport import RIPPClientTransport
from labs.lab1.src.lab1_protocol.RIPPPacket import RIPPPacket
from labs.lab1.src.lab1_protocol.RIPPPacketType import RIPPPacketType, max_seq_no, StateType


class RIPPClientProtocol(StackingProtocol):

    def __init__(self):
        self.transport = None
        self.deserializer = None
        self.receive_window = OrderedDict()
        self.sending_window = OrderedDict()
        self.state = StateType.CLOSED.value
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
            if isinstance(pkt, RIPPPacket) and pkt.validate(pkt):
                if self.state == StateType.CLOSED.value:
                    if pkt.Type == RIPPPacketType.SYN_ACK.value:
                        print("Received SYN ACK {}".format(pkt))
                        self.receive_syn_ack_packet(pkt)
                    elif pkt.Type == RIPPPacketType.ACK.value:
                        print("Received SYN ACK ACK {}".format(pkt))
                        self.receive_syn_ack_ack_packet(pkt)
                    elif pkt.Type == RIPPPacketType.SYN.value:
                        print("Received SYN {}".format(pkt))
                        self.receive_syn_packet(pkt)
                elif self.state == StateType.OPEN.value:
                    if pkt.Type == RIPPPacketType.DATA.value:
                        print("Received Data {}".format(pkt))
                        self.receive_data_packet(pkt)
                    elif pkt.Type == RIPPPacketType.ACK.value:
                        print("Received ACK {}".format(pkt))
                        self.receive_ack_packet(pkt)
                    elif pkt.Type == RIPPPacketType.FIN.value:
                        print("Received FIN {}".format(pkt))
                        self.receive_fin_packet(pkt)
                    elif pkt.Type == RIPPPacketType.FIN_ACK.value:
                        print("Received FIN-ACK {}".format(pkt))
                        self.receive_fin_ack_packet(pkt)
            else:
                self.connection_lost("---> Found error in packet {}".format(pkt))

    # ---------- Custom methods ---------------- #
    def establish_connection(self, pkt):
        higher_protocol = RIPPClientTransport(self, self.transport)
        higher_protocol.start_seq(pkt.AckNo)
        self.higherProtocol().connection_made(higher_protocol)
        self.state = StateType.OPEN.value
        print("----> Connection Established")
        # self.transport.start_seq(pkt.AckNo)

    # ---------- Send Packets ---------------- #

    def send_syn_ack_packet(self, pkt):
        print("Sending SYN ACK")
        seq = random.randrange(100, max_seq_no // 100)
        syn_ack = RIPPPacket().syn_ack_packet(seq_no=seq, ack_no=pkt.SeqNo + 1)
        self.receive_window[seq] = syn_ack
        self.transport.write(syn_ack.__serialize__())
        print("SYN-ACK Sent")

    def send_syn_packet(self):
        seq = random.randrange(100, max_seq_no // 100)
        syn = RIPPPacket().syn_packet(seq_no=seq)
        print("Sending SYN {}".format(syn))
        self.receive_window[seq] = syn
        self.transport.write(syn.__serialize__())
        print("SYN Sent")

    def send_ack_packet(self, syn_ack):
        ack = RIPPPacket().ack_packet(seq_no=syn_ack.AckNo, ack_no=syn_ack.SeqNo + 1)
        print("Sending ACK {}".format(ack))
        self.transport.write(ack.__serialize__())
        print("ACK Sent")

    def send_data_ack_packet(self, pkt):
        data_ack = RIPPPacket().ack_packet(ack_no=pkt.SeqNo + len(pkt.Data))
        print("Sending Data ACK {}".format(data_ack))
        self.transport.write(data_ack.__serialize__())
        print("ACK sent for data. Sending upstream")
        self.higherProtocol().data_received(pkt.Data)
        self.receive_window.pop(pkt.SeqNo)

    def send_fin_ack_packet(self, fin):
        fin_ack = RIPPPacket().fin_ack_packet(seq_no=fin.AckNo, ack_no=fin.SeqNo + 1)
        print("Sending FIN-ACK {}".format(fin_ack))
        self.transport.write(fin_ack.__serialize__())
        print("FIN-ACK Sent")

    def chunk_data_packets(self, seq_no, pkt):
        print("Chunking data packet {}".format(pkt))
        seq_no_len = seq_no
        for pkt_chunk in [pkt[i:i + 1500] for i in range(0, len(pkt), 1500)]:
            data = RIPPPacket().data_packet(seq_no=seq_no, data_content=pkt_chunk)
            seq_no_len = seq_no + len(pkt_chunk)
            seq_no += 1
            self.sending_window[seq_no_len] = data
        return seq_no_len

    def send_data_packets(self):
        for seq_no, data_chunk in self.sending_window.copy().items():
            print("Sending Data down the wire {}".format(data_chunk))
            self.transport.write(data_chunk.__serialize__())

    # ---------- Receive Packets ---------------- #

    def receive_syn_packet(self, syn):
        if syn.validate(syn):
            self.send_syn_ack_packet(syn)
        else:
            self.connection_lost("Invalid SYN Packet received from the client")

    def receive_data_packet(self, pkt):
        if pkt.validate(pkt):
            # TODO: Add SeqNo check
            print("Data received with len {} {}".format(len(pkt.Data), pkt))
            self.receive_window[pkt.SeqNo] = pkt
            self.send_data_ack_packet(pkt)  # TODO: run in seprate thread
        else:
            self.connection_lost("Invalid Data Packet received from the server {}".format(pkt.SeqNo))

    def receive_syn_ack_packet(self, syn_ack):
        if syn_ack.validate(syn_ack) and syn_ack.AckNo - 1 in self.receive_window:
            self.receive_window.pop(syn_ack.AckNo - 1)
            self.send_ack_packet(syn_ack)
            self.establish_connection(syn_ack)
        else:
            self.connection_lost("Invalid SYN ACK Packet received from the server")

    def receive_ack_packet(self, pkt):
        if pkt.validate(pkt) and pkt.AckNo in self.sending_window:
            print("Popping from ACK window")
            self.sending_window.pop(pkt.AckNo)
        else:
            self.connection_lost("Invalid Data ACK Packet received from the client")

    def receive_syn_ack_ack_packet(self, pkt):
        if pkt.validate(pkt) and pkt.AckNo - 1 in self.receive_window:
            print("Popping from SYNACKACK window")
            self.receive_window.pop(pkt.AckNo - 1)
            self.establish_connection(pkt)
        else:
            self.connection_lost("Invalid SYN ACK ACK Packet received from the client")

    def receive_fin_packet(self, fin):
        if fin.validate(fin):
            # TODO: take care of the buffer here
            self.send_fin_ack_packet(fin)
        else:
            self.connection_lost("Invalid FIN Packet received from the server")

    def receive_fin_ack_packet(self, pkt):
        if pkt.validate(pkt):
            self.transport.close()
        else:
            self.connection_lost("Invalid FIN-ACK Packet received from the server")
