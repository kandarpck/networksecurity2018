import secrets
from logging import getLogger, DEBUG

from playground.network.common import StackingProtocol

from .CertificateUtil import ClientCertificateUtils
from .CipherUtil import ClientCipherUtils
from .SITHPacket import SITHPacket
from .SITHPacketType import SITHPacketType
from .SITHTransport import SithTransport

logger = getLogger('playground.' + __name__)
logger.setLevel(DEBUG)


class SithClientProtocol(StackingProtocol):
    def __init__(self):
        super(SithClientProtocol, self).__init__()
        self.ProtocolID = 'CLIENT'
        self.SithTransport = None
        self.transport = None
        self.address = None
        self.client_ciphers = ClientCipherUtils()
        self.client_certs = ClientCertificateUtils(self.address)
        self.client_hello = None
        self.deserializer = SITHPacket.Deserializer()

    def connection_made(self, transport):
        self.transport = transport
        # Make connection
        logger.debug('\n SITH CLIENT MAKING CONNECTION \n')
        self.SithTransport = SithTransport(self)
        self.client_hello = SITHPacket().sith_hello(random=secrets.randbits(256),
                                                    public_val=self.client_ciphers.public_key,
                                                    certs=[self.client_certs.client_cert,
                                                           self.client_certs.intermediate_cert,
                                                           self.client_certs.get_root_certificate()])

    def data_received(self, data):
        logger.debug('\n SITH Client received data. \n')
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if pkt.Type == SITHPacketType.DATA.value:
                pass
            elif pkt.Tyoe == SITHPacketType.HELLO.value:
                pass
            elif pkt.Type == SITHPacketType.FINISH.value:
                pass
            elif pkt.Type == SITHPacketType.CLOSE.value:
                pass
            else:
                logger.error('Unexpected packet type found')  # TODO drop?

        self.higherProtocol().data_received(data)

        self.higherProtocol().connection_made(self.SithTransport)

    def connection_lost(self, exc):
        logger.error('\n SITH CLIENT: Connection to server lost.\n')
        self.transport = None
