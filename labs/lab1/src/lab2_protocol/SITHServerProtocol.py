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

#TODO: Complete handshake

class SithServerProtocol(StackingProtocol):
    def __init__(self):
        super(SithServerProtocol, self).__init__()
        self.ProtocolID = 'SERVER'
        self.SithTransport = None
        self.transport = None
        self.state = StateType.LISTEN.value
        self.address = None
        self.cipher_util = ServerCipherUtils()
        self.server_certs = ServerCertificateUtils(self.address)
        self.deserializer = SITHPacket.Deserializer()
        self.server_hello = None

    # ---------- Overridden methods ---------------- #

    def connection_made(self, transport):
        logger.debug('\n SITH Server connection made with {}\n'.format(transport.get_extra_info('peername')))
        self.transport = transport

    def data_received(self, data):
        logger.debug('\n SITH Server received data. \n')
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if self.state == StateType.ESTABLISHED.value:
                # Expecting Data or Close packets
                if pkt.Type == SITHPacketType.DATA.value:
                    pt = self.cipher_util.client_decrypt(pkt.Ciphertext)
                    self.higherProtocol().data_received(pt)
                elif pkt.Type == SITHPacketType.CLOSE.value:
                    # Close Connection
                    self.higherProtocol().connection_lost(pkt.Ciphertext)
                    self.transport.close()
                    self.state = StateType.CLOSED.value
                else:
                    logger.error('Unexpected packet type found')  # TODO drop?
            elif self.state == StateType.LISTEN.value:
                # Only expecting HELLO packet from Client
                if pkt.Type == SITHPacketType.HELLO.value:
                    if self.server_certs.validate_certificate_chain(pkt.Certificate):
                        self.state = StateType.HELLO_RECEIVED
                        # Send Client the Server HELLO to continue handshake
                        self.server_hello = SITHPacket().sith_hello(random=secrets.randbits(256),
                                                                    public_val=self.cipher_util.public_key,
                                                                    certs=[self.server_certs.server_cert,
                                                                           self.server_certs.intermediate_cert,
                                                                           self.server_certs.get_root_certificate()])
                        logger.debug('\n SITH SERVER: SENDING HELLO PACKET\n')
                        self.transport.write(self.server_hello.__serialize__())

                       # Key Derivation
                        client_iv, server_iv, server_write, server_read = self.cipher_util.generate_server_keys(
                            self.server_hello, pkt)

                        # Send FINISH Packet TODO: Change to ECDSA signature
                        signature = self.cipher_util.get_signature(self.client_hello, pkt)
                        finish_pkt = SITHPacket().sith_finish(signature)
                        self.transport.write(finish_pkt.__serialize__())
                    else:
                        logger.error("Error in certificate chain validation {}".format(pkt))
                else:
                    logger.error('Unexpected packet type found')  # TODO drop?
            elif self.state == StateType.HELLO_RECEIVED.value:
                # Expecting FINISH packet from Client
                if pkt.Type == SITHPacketType.FINISH.value:
                    # TODO: Verify signatures
                    if self.cipher_util.verify_signature(pkt.Signature):
                        # Establish connection
                        logger.debug('\n SITH CLIENT MAKING CONNECTION \n')
                        self.SithTransport = SithTransport(self)
                        self.higherProtocol().connection_made(self.SithTransport)
                        self.state = StateType.ESTABLISHED.value
                    else:
                        logger.error('Signature Validation Error')
                else:
                    logger.error('Unexpected packet type found')  # TODO drop?
            else:
                logger.error('Unexpected state found')  # TODO drop?

    def connection_lost(self, exc):
        logger.error('\n SITH SERVER: Connection to client lost.\n')
        self.transport = None
