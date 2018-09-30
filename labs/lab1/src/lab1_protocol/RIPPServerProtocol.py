from .RIPPPacket import RIPPPacket
from playground.network.common import StackingProtocol


class RIPPServerProtocol(StackingProtocol):

    def __init__(self):
        self.transport = None
        super(RIPPServerProtocol, self).__init__()

    # ---------- Overridden methods ---------------- #

    def connection_made(self, transport):
        self.transport = transport
        self.higherProtocol().connection_made(self.transport)

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)

    def data_received(self, data):
        self.higherProtocol().data_received(data)

    # ---------- Custom methods ---------------- #