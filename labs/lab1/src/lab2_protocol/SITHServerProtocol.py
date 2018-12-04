import secrets
from logging import getLogger, WARNING

from playground.network.common import StackingProtocol

from .CertificateUtil import ServerCertificateUtils
from .CipherUtil import ServerCipherUtils
from .SITHPacket import SITHPacket
from .SITHPacketType import SITHPacketType, StateType
from .SITHTransport import SithTransport

logger = getLogger('playground.' + __name__)
logger.setLevel(WARNING)


class SithServerProtocol(StackingProtocol):
    def __init__(self):
        super(SithServerProtocol, self).__init__()
        self.ProtocolID = 'SERVER'
        self.SithTransport = None
        self.transport = None
        self.state = StateType.LISTEN.value
        self.address = None
        self.cipher_util = ServerCipherUtils()
        self.server_certs = ServerCertificateUtils()
        self.deserializer = SITHPacket.Deserializer()
        self.server_hello = None
        self.peer_pub_key = None

    # ---------- Overridden methods ---------------- #

    def connection_made(self, transport):
        logger.debug('\n SITH Server connection made with {}\n'.format(transport.get_extra_info('peername')))
        self.transport = transport

    def data_received(self, data):
        logger.debug('\n SITH Server received data. \n')
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            # If CLOSE is received during any STATE, connection will be closed.
            if pkt.Type == SITHPacketType.CLOSE.value:
                # Close connection
                self.close_connection()
            elif self.state == StateType.ESTABLISHED.value:
                # Expecting Data
                if pkt.Type == SITHPacketType.DATA.value:
                    pt = self.cipher_util.client_decrypt(pkt.Ciphertext)
                    self.higherProtocol().data_received(pt)
                else:
                    logger.error('SITH Protocol unexpected packet type found in {} state'.format(self.state))
            elif self.state == StateType.LISTEN.value:
                # Expecting HELLO packet from Client
                if pkt.Type == SITHPacketType.HELLO.value:
                    if self.server_certs.validate_certificate_chain(pkt.Certificate):
                        self.state = StateType.HELLO_RECEIVED.value
                        self.peer_pub_key = self.server_certs.get_peer_public_key(pkt.Certificate)

                        # Send Client the Server HELLO to continue handshake
                        self.server_hello = SITHPacket().sith_hello(random=secrets.token_bytes(32),
                                                                    public_val=self.cipher_util.public_key.public_bytes(),
                                                                    certs=[self.server_certs.server_cert,
                                                                           self.server_certs.intermediate_cert,
                                                                           self.server_certs.get_root_certificate()])
                        logger.debug('\n SITH SERVER: SENDING HELLO PACKET\n')
                        self.transport.write(self.server_hello.__serialize__())

                        # Key Derivation
                        logger.debug('\n SITH SERVER: DERIVING KEYS\n')
                        shared = self.cipher_util.generate_server_shared(pkt.PublicValue)
                        client_iv, server_iv, server_write, server_read = self.cipher_util.generate_server_keys(
                            pkt.__serialize__(), self.server_hello.__serialize__())

                        # Send FINISH Packet
                        signature = self.cipher_util.get_signature(pkt.__serialize__(),
                                                                   self.server_hello.__serialize__())
                        finish_pkt = SITHPacket().sith_finish(signature)
                        logger.debug('\n SITH SERVER: SENDING FINISH PACKET\n')
                        self.transport.write(finish_pkt.__serialize__())
                    else:
                        self.send_close("Error in certificate chain validation {}".format(pkt))
                else:
                    logger.error('SITH Protocol unexpected packet type found in {} state'.format(self.state))
            elif self.state == StateType.HELLO_RECEIVED.value:
                # Expecting FINISH packet from Client
                if pkt.Type == SITHPacketType.FINISH.value:
                    # Verify signatures
                    if self.cipher_util.verify_signature(self.peer_pub_key, pkt.Signature):
                        # Establish connection
                        logger.debug('\n SITH CLIENT MAKING CONNECTION \n')
                        self.SithTransport = SithTransport(self)
                        self.higherProtocol().connection_made(self.SithTransport)
                        self.state = StateType.ESTABLISHED.value
                    else:
                        self.send_close('Signature Validation Error')
                else:
                    logger.error('SITH Protocol unexpected packet type found in {} state'.format(self.state))
            else:
                logger.error('SITH Protocol receiving data in unexpected state')

    def connection_lost(self, exc):
        logger.error('\n SITH SERVER: Connection to client lost.\n')
        self.transport = None

# ------------- Custom Methods -------------------#

    def send_close(self, error):
        logger.error(error)
        # Create Close packet with error message
        close_pkt = SITHPacket().sith_close(error)
        self.transport.write(close_pkt.__serialize__())
        self.close_connection(error)

    def close_connection(self, error=None):
        # Close transports
        self.higherProtocol().connection_lost(error)
        self.transport.close()
        self.state = StateType.CLOSED.value
