import secrets
from logging import getLogger, DEBUG

from playground.network.common import StackingProtocol

from .CertificateUtil import ServerCertificateUtils
from .CipherUtil import ServerCipherUtils
from .SITHPacket import SITHPacket
from .SITHPacketType import SITHPacketType
from .SITHTransport import SithTransport

logger = getLogger('playground.' + __name__)
logger.setLevel(DEBUG)


class SithServerProtocol(StackingProtocol):
    def __init__(self):
        super(SithServerProtocol, self).__init__()
        self.ProtocolID = 'SERVER'
        self.SithTransport = None
        self.transport = None
        self.address = None
        self.server_ciphers = ServerCipherUtils()
        self.server_certs = ServerCertificateUtils(self.address)
        self.deserializer = SITHPacket.Deserializer()
        self.server_hello = None

    # ---------- Overridden methods ---------------- #

    def connection_made(self, transport):
        self.transport = transport
        # Make connection
        logger.debug('\n SITH SERVER MAKING CONNECTION \n')
        self.SithTransport = SithTransport(self)
        self.server_hello = SITHPacket().sith_hello(random=secrets.randbits(256),
                                                    public_val=self.server_ciphers.public_key,
                                                    certs=[self.server_certs.server_cert,
                                                           self.server_certs.intermediate_cert,
                                                           self.server_certs.get_root_certificate()])

    def data_received(self, data):
        logger.debug('\n SITH Client received data. \n')
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if pkt.Type == SITHPacketType.DATA.value:
                pt = self.server_ciphers.client_decrypt(pkt.Ciphertext)
                self.higherProtocol().data_received(pt)
            elif pkt.Type == SITHPacketType.HELLO.value:
                if self.server_certs.validate_certificate_chain(pkt.Certificate):
                    client_iv, server_iv, server_write, server_read = self.server_ciphers.generate_server_keys(
                        self.server_hello, pkt)
                else:
                    logger.error("Error in certificate chain validation {}".format(pkt))
            elif pkt.Type == SITHPacketType.FINISH.value:

                self.higherProtocol().connection_made(self.SithTransport)

            elif pkt.Type == SITHPacketType.CLOSE.value:
                self.higherProtocol().connection_lost(pkt.Ciphertext)
                self.transport.close()
            else:
                logger.error('Unexpected packet type found')  # TODO drop?

        self.higherProtocol().data_received(data)
        self.higherProtocol().connection_made(self.SithTransport)

    def connection_lost(self, exc):
        logger.error('\n SITH SERVER: Connection to client lost.\n')
        self.transport = None
