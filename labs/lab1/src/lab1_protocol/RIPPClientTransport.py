from playground.network.common import StackingTransport


class RIPPClientTransport(StackingTransport):

    def __init__(self):
        super(RIPPClientTransport, self).__init__()

    def write(self, data):
        pass
