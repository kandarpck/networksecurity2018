from logging import getLogger, WARNING, DEBUG

from playground.network.common import StackingProtocol

# from .PacketHandler import PacketHandler
# from .RIPPPacket import RIPPPacket
# from .RIPPPacketType import RIPPPacketType, StateType
from .SITHTransport import SithTransport

logger = getLogger('playground.' + __name__)
logger.setLevel(DEBUG)


class SithServerProtocol(StackingProtocol):
    def __init__(self):
        super(SithServerProtocol, self).__init__()
        self.ProtocolID = 'SERVER'
        self.SithTransport = None
        self.transport = None

    # ---------- Overridden methods ---------------- #

    def connection_made(self, transport):
        logger.debug('\n SITH Server connection made with {}\n'.format(transport.get_extra_info('peername')))
        self.transport = transport
        # Make connection
        logger.debug('\n SITH SERVER MAKING CONNECTION \n')
        self.SithTransport = SithTransport(self)
        self.higherProtocol().connection_made(self.SithTransport)

    def data_received(self, data):
        logger.debug('\n SITH Server received data. Pushing data up.\n')
        self.higherProtocol().data_received(data)

    def connection_lost(self, exc):
        logger.error('\n SITH SERVER: Connection to client lost.\n')
        self.transport = None
