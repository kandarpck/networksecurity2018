import logging

from playground.network.common import StackingTransport

from .SITHPacket import SITHPacket

logger = logging.getLogger('playground.' + __name__)
logger.setLevel(logging.WARNING)


class SithTransport(StackingTransport):
    def __init__(self, lower_protocol):
        self.Protocol = lower_protocol
        super().__init__(lower_protocol.transport)

    def write(self, data):
        print("\nSITH {} Transport writing data\n".format(self.Protocol.ProtocolID))
        # Encrypt data and send Data packet
        ct = self.Protocol.cipher_util.encrypt_data(data)
        data_pkt = SITHPacket().sith_data(ct)
        self.lowerTransport().write(data_pkt.__serialize__())

    def close(self):
        self.Protocol.close_connection('Close request received from higher protocol')
