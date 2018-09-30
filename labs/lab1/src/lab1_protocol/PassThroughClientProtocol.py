from playground.network.common import StackingProtocol


class PassThroughClientProtocol(StackingProtocol):

    def __init__(self):
        self.transport = None
        super(PassThroughClientProtocol, self).__init__()

    def connection_made(self, transport):
        pass

    def connection_lost(self, exc):
        pass

    def data_received(self, data):
        pass
