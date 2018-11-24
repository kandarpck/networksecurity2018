from logging import getLogger, WARNING, DEBUG

from playground.network.common import StackingProtocol

# from .PacketHandler import PacketHandler
# from .RIPPPacket import RIPPPacket
# from .RIPPPacketType import RIPPPacketType, StateType
from .SITHTransport import SithTransport

logger = getLogger('playground.' + __name__)
logger.setLevel(DEBUG)


class SithClientProtocol(StackingProtocol):
    def __init__(self):
        super(SithClientProtocol, self).__init__()
        self.ProtocolID = 'CLIENT'
        self.SithTransport = None
        self.transport = None

    def connection_made(self, transport):
        logger.debug('\n SITH Client connection made with {}\n'.format(transport.get_extra_info('peername')))
        self.transport = transport
        # Make connection
        logger.debug('\n SITH CLIENT MAKING CONNECTION \n')
        self.SithTransport = SithTransport(self)
        self.higherProtocol().connection_made(self.SithTransport)

    def data_received(self, data):
        logger.debug('\n SITH Client received data. Pushing data up.\n')
        self.higherProtocol().data_received(data)

    def connection_lost(self, exc):
        logger.error('\n SITH CLIENT: Connection to server lost.\n')
        self.transport = None
