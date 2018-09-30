from playground.network.common import StackingProtocol


class PassThroughServerProtocol(StackingProtocol):

    def __init__(self):
        self.transport = None
        super(PassThroughServerProtocol, self).__init__()

    def connection_made(self, transport):
        pass

    def connection_lost(self, exc):
        pass

    def data_received(self, data):
        pass
