from playground.network.common import StackingProtocol


class PassThroughClientProtocol(StackingProtocol):

    def __init__(self):
        self.transport = None
        super(PassThroughClientProtocol, self).__init__()

    def connection_made(self, transport):
        print("Connected to {}".format(transport.get_extra_info("peername")))

    def connection_lost(self, exc):
        pass

    def data_received(self, data):
        pass
