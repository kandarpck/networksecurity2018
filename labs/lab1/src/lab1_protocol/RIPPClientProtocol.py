from labs.lab1.src.lab1_protocol.RIPPPacket import RIPPPacket
from playground.network.common import StackingProtocol
from datetime import datetime


class RIPPClientProtocol(StackingProtocol):

    def __init__(self):
        self.transport = None
        self.deserializer = None
        super(RIPPClientProtocol, self).__init__()

    # ---------- Overridden methods ---------------- #

    def connection_made(self, transport):
        self.transport = transport
        self.deserializer = RIPPPacket.Deserializer()
        self.higherProtocol().connection_made(self.transport)

        # Start three-way handshake
        print('Starting three-way handshake with {} at {}'.format(
            transport.get_extra_info("peername"),
            datetime.now()

        ))
        self.send_syn_packet()

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)

    def data_received(self, data):
        self.higherProtocol().data_received(data)

    # ---------- Custom methods ---------------- #

    def send_syn_packet(self):
        syn = RIPPPacket().syn_packet()


