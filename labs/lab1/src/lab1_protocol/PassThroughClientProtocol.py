from playground.network.common import StackingProtocol


class PassThroughClientProtocol(StackingProtocol):

    def __init__(self):
        self.transport = None
        super(PassThroughClientProtocol, self).__init__()

    def connection_made(self, transport):
        print("Connected via passthrough layer")
        self.transport = transport
        self.higherProtocol().connection_made(self.transport)

    def connection_lost(self, exc):
        print("Disconnected from passthrough layer")
        if not exc:
            print("Terminating connection gracefully")
        else:
            print("Terminating connection with execption {}".format(exc))
        self.higherProtocol().connection_lost(exc)

    def data_received(self, data):
        print("Passthrough layer received data of size {}".format(len(data)))
        self.higherProtocol().data_received(data)
