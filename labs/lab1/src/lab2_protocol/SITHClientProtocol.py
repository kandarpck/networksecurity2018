import secrets
import asyncio
from logging import getLogger, DEBUG

from playground.network.common import StackingProtocol

from .CertificateUtil import ClientCertificateUtils
from .CipherUtil import ClientCipherUtils
from .SITHPacket import SITHPacket
from .SITHPacketType import SITHPacketType, StateType
from .SITHTransport import SithTransport

logger = getLogger('playground.' + __name__)
logger.setLevel(DEBUG)


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
        self.peer_pub_key = None
        self.hello_timer = None

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
                    logger.error('Unexpected packet type found')
            elif self.state == StateType.HELLO_SENT.value:
                # Only packet expected is HELLO from the server
                if pkt.Type == SITHPacketType.HELLO.value:
                    # Continue handshake
                    if self.client_certs.validate_certificate_chain(pkt.Certificate):
                        self.hello_timer.cancel()
                        self.state = StateType.HELLO_RECEIVED.value
                        self.peer_pub_key = self.client_certs.get_peer_public_key(pkt.Certificate)
                        # Key Derivation
                        logger.debug('\n SITH CLIENT: DERIVING KEYS\n')
                        shared = self.cipher_util.generate_client_shared(pkt.PublicValue)
                        client_iv, server_iv, client_read, client_write = self.cipher_util.generate_client_keys(
                            self.client_hello.__serialize__(), pkt.__serialize__())
                        # Send FINISH Packet TODO: Change to ECDSA signature
                        signature = self.cipher_util.get_signature(self.client_hello.__serialize__(),
                                                                   pkt.__serialize__())
                        finish_pkt = SITHPacket().sith_finish(signature)
                        print('Sending keys for verification \n {}'.format(finish_pkt))
                        logger.debug('\n SITH CLIENT: SENDING FINISH PACKET\n')
                        self.transport.write(finish_pkt.__serialize__())
                    else:
                        logger.error("Error in certificate chain validation {}".format(pkt))
                else:
                    logger.error('Unexpected packet type found')  # TODO drop?
            elif self.state == StateType.HELLO_RECEIVED.value:
                # Expecting FINISH packet from server
                if pkt.Type == SITHPacketType.FINISH.value:
                    # TODO: Verify signatures
                    if self.cipher_util.verify_signature(self.peer_pub_key, pkt.Signature):
                        # Establish connection
                        logger.debug('\n SITH CLIENT MAKING CONNECTION \n')
                        self.SithTransport = SithTransport(self)
                        self.higherProtocol().connection_made(self.SithTransport)
                        self.state = StateType.ESTABLISHED.value
                    else:
                        self.close_connection('Signature Validation Error')
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
        if self.state == StateType.LISTEN.value:
            self.client_hello = SITHPacket().sith_hello(random=secrets.token_bytes(32),  # 32 bytes = 256 bits
                                                        public_val=self.cipher_util.public_key.public_bytes(),
                                                        certs=[self.client_certs.client_cert,
                                                               self.client_certs.intermediate_cert,
                                                               self.client_certs.get_root_certificate()])
            logger.debug('\n SITH CLIENT: SENDING HELLO PACKET\n')
            self.transport.write(self.client_hello.__serialize__())
            self.state = StateType.HELLO_SENT.value
            # Start timer for Hello packets.  Timer is cancelled when peer Hello is received.
            self.hello_timer = asyncio.get_event_loop().call_later(1, self.resend_HELLO, self.client_hello)

    def resend_HELLO(self, hello):
        logger.debug('\n SITH CLIENT: RESENDING HELLO PACKET\n')
        self.transport.write(hello.__serialize__())
        # Restart timer
        self.hello_timer = asyncio.get_event_loop().call_later(1, self.resend_HELLO, hello)

    def close_connection(self, error):
        logger.error(error)
        # Create Close packet with error message
        close_pkt = SITHPacket().sith_close(error)
        self.transport.write(close_pkt.__serialize__())

        # Close transports
        self.higherProtocol().connection_lost(error)
        self.transport.close()
        self.state = StateType.CLOSED.value
