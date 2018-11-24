import logging

from playground.network.common import StackingTransport

from .SITHPacket import SITHPacket
from .SITHPacketType import StateType

logger = logging.getLogger('playground.' + __name__)
logger.setLevel(logging.WARNING)


class SithTransport(StackingTransport):
    # Store all sent data packets in protocol's pktHdlr
    # Add timer for all data packets sent
    def __init__(self, lower_protocol):
        self.Protocol = lower_protocol
        super().__init__(lower_protocol.transport)

    def write(self, data):
        print("\nSITH {} Transport writing data\n".format(self.Protocol.ProtocolID))
        self.lowerTransport().write(data)

    def close(self):
        self.Protocol.higherProtocol().connection_lost(None)
        self.Protocol.transport.close()
