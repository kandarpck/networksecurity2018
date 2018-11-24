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
        self.deserializer = SITHPacket.Deserializer()
        self.client_hello = None

    # ---------- Overridden methods ---------------- #

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
                pt = self.client_ciphers.server_decrypt(pkt.Ciphertext)
                self.higherProtocol().data_received(pt)
            elif pkt.Type == SITHPacketType.HELLO.value:
                client_iv, server_iv, client_read, client_write = self.client_ciphers.generate_client_keys(
                    self.client_hello, pkt)

            elif pkt.Type == SITHPacketType.FINISH.value:

                self.higherProtocol().connection_made(self.SithTransport)

            elif pkt.Type == SITHPacketType.CLOSE.value:
                self.higherProtocol().connection_lost(pkt.Ciphertext)
                self.transport.close()
            else:
                logger.error('Unexpected packet type found')  # TODO drop?

    def connection_lost(self, exc):
        logger.error('\n SITH CLIENT: Connection to server lost.\n')
        self.transport.close()
        self.transport = None
