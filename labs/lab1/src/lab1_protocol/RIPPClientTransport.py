from playground.network.common import StackingTransport


class RIPPClientTransport(StackingTransport):

    def __init__(self, protocol, transport):
        self.protocol = protocol
        self.transport = transport
        super(RIPPClientTransport, self).__init__(self.transport)

    def write(self, data):
        pass
