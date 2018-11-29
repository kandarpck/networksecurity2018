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

# TODO: Add handshake

class SithClientProtocol(StackingProtocol):
    def __init__(self):
        super(SithClientProtocol, self).__init__()
        self.ProtocolID = 'CLIENT'
        self.SithTransport = None
        self.transport = None
        self.state = StateType.LISTEN.value
        self.address = None
        self.cipher_util = ClientCipherUtils()
        self.client_certs = ClientCertificateUtils(self.address)
        self.deserializer = SITHPacket.Deserializer()
        self.client_hello = None

    # ---------- Overridden methods ---------------- #

    def connection_made(self, transport):
        logger.debug('\n SITH Client connection made with {}\n'.format(transport.get_extra_info('peername')))
        self.transport = transport

        # Initiate Handshake
        self.initiate_handshake()

    def data_received(self, data):
        logger.debug('\n SITH Client received data. \n')
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            if self.state == StateType.ESTABLISHED.value:
                # Expecting Data or Close packets
                if pkt.Type == SITHPacketType.DATA.value:
                    pt = self.cipher_util.server_decrypt(pkt.Ciphertext)
                    self.higherProtocol().data_received(pt)
                elif pkt.Type == SITHPacketType.CLOSE.value:
                    # Close connection
                    self.higherProtocol().connection_lost(pkt.Ciphertext)
                    self.transport.close()
                    self.state = StateType.CLOSED.value
                else:
                    logger.error('Unexpected packet type found')  # TODO drop?
            elif self.state == StateType.HELLO_SENT.value:
                # Only packet expected is HELLO from the server
                if pkt.Type == SITHPacketType.HELLO.value:
                    # Continue handshake
                    if self.client_certs.validate_certificate_chain(pkt.Certificate):
                        # Key Derivation
                        client_iv, server_iv, client_read, client_write = self.cipher_util.generate_client_keys(
                            self.client_hello, pkt)
                    else:
                        logger.error("Error in certificate chain validation {}".format(pkt))

                    # Send FINISH Packet TODO: Change to ECDSA signature
                    signature = self.cipher_util.get_signature(self.client_hello, pkt)
                    finish_pkt = SITHPacket().sith_finish(signature)
                    self.transport.write(finish_pkt.__serialize__())
                else:
                    logger.error('Unexpected packet type found')  # TODO drop?
            elif self.state == StateType.HELLO_RECEIVED.value:
                # Expecting FINISH packet from server
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
        logger.error('\n SITH CLIENT: Connection to server lost.\n')
        self.transport = None

    # ---------- Custom methods ---------------- #

    def initiate_handshake(self):
        # Create Hello Packet to initiate session
        if self.state == self.StateType.LISTEN.value:
            self.client_hello = SITHPacket().sith_hello(random=secrets.randbits(256),
                                                        public_val=self.cipher_util.public_key,
                                                        certs=[self.client_certs.client_cert,
                                                               self.client_certs.intermediate_cert,
                                                               self.client_certs.get_root_certificate()])
            logger.debug('\n SITH CLIENT: SENDING HELLO PACKET\n')
            self.transport.write(self.client_hello.__serialize__())
            self.state = StateType.HELLO_SENT.value
            # TODO: Add timer for HELLO resend?
