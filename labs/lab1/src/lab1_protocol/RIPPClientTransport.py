from playground.network.common import StackingTransport


class RIPPClientTransport(StackingTransport):

    def __init__(self, protocol, transport):
        self.protocol = protocol
        self.transport = transport
        self.seq_no = None
        super(RIPPClientTransport, self).__init__(self.transport)

    def write(self, data):
        self.seq_no = self.protocol.chunk_data_packets(self.seq_no, data)
        self.protocol.send_data_packets()

    def start_seq(self, seq):
        self.seq_no = seq
