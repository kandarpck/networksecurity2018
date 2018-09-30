from playground.network.common import StackingTransport


class RIPPServerTransport(StackingTransport):

    def __init__(self):
        super(RIPPServerTransport, self).__init__()

    def write(self, data):
        pass
