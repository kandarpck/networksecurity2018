import logging

from playground.network.common import StackingTransport

from .SITHPacket import SITHPacket
from .SITHPacketType import StateType

logger = logging.getLogger('playground.' + __name__)
logger.setLevel(logging.WARNING)

# TODO: Add encrypt data with shared key when writing data down the stack.
# TODO: Check if connection was made?

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
        # Create and send CLOSE packet
        close_pkt = SITHPacket().sith_close()
        self.Protocol.transport.write(close_pkt.__serialize__())
        self.Protocol.transport.close()
