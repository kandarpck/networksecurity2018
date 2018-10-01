from playground.network.common import StackingTransport


class RIPPClientTransport(StackingTransport):

    def __init__(self, protocol, lower_transport):
        self.protocol = protocol
        self.seq_no = None
        super(RIPPClientTransport, self).__init__(lower_transport)

    def write(self, data):
        self.seq_no = self.protocol.chunk_data_packets(self.seq_no, data)
        self.protocol.send_data_packets()

    def start_seq(self, seq):
        self.seq_no = seq
