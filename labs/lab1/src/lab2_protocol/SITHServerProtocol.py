import secrets
from logging import getLogger, DEBUG

from playground.network.common import StackingProtocol

from .CertificateUtil import ServerCertificateUtils
from .CipherUtil import ServerCipherUtils
from .SITHPacket import SITHPacket
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

    # ---------- Overridden methods ---------------- #

    def connection_made(self, transport):
        self.transport = transport
        # Make connection
        logger.debug('\n SITH SERVER MAKING CONNECTION \n')
        self.SithTransport = SithTransport(self)
        server_hello = SITHPacket().sith_hello(random=secrets.randbits(256),
                                               public_val=self.server_ciphers.public_key,
                                               certs=[self.server_certs.server_cert,
                                                      self.server_certs.intermediate_cert,
                                                      self.server_certs.get_root_certificate()])
        self.higherProtocol().connection_made(self.SithTransport)

    def data_received(self, data):
        logger.debug('\n SITH Server received data. Pushing data up.\n')
        self.higherProtocol().data_received(data)

    def connection_lost(self, exc):
        logger.error('\n SITH SERVER: Connection to client lost.\n')
        self.transport = None
