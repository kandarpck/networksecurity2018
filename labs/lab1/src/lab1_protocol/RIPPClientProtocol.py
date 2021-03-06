import asyncio
from logging import getLogger, WARNING
from random import randint

from playground.network.common import StackingProtocol

from .PacketHandler import PacketHandler
from .RIPPPacket import RIPPPacket
from .RIPPPacketType import RIPPPacketType, StateType
from .RIPPTransport import RippTransport

logger = getLogger('playground.' + __name__)
logger.setLevel(WARNING)


class RippClientProtocol(StackingProtocol):
    def __init__(self):
        super(RippClientProtocol, self).__init__()
        self.ProtocolID = 'CLIENT'
        self.RippTransport = None
        self.transport = None
        self.deserializer = RIPPPacket.Deserializer()
        self.pktHdlr = PacketHandler(self)
        self.state = StateType.LISTEN.value
        self.seqID = randint(0, 2 ** 32)
        self.ackID = 0
        self.finSent = False
        self.synTimer = None

    def connection_made(self, transport):
        logger.debug('\n Client connection made with {}\n'.format(transport.get_extra_info('peername')))
        self.transport = transport

        # Initiate Handshake
        self.initiate_handshake()

    def data_received(self, data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            logger.debug('\n RIPP Client: {} received\n'.format(pkt))

            if not pkt.validate(pkt):  # not isinstance(pkt, RIPPPacket) and
                logger.error('\n RIPP Client: INVALID PACKET TYPE RECEIVED \n')
                continue
                # self.transport.close()

            elif self.state == StateType.ESTABLISHED.value:

                if RIPPPacketType.DATA.value == pkt.Type:  # type Data
                    logger.debug('\n RIPP CLIENT: RECEIVED DATA PACKET S:{} \n'.format(pkt.SeqNo))
                    # Process Data Packet and send ACK
                    self.pktHdlr.process_data(pkt)

                elif RIPPPacketType.ACK.value == pkt.Type:  # type ACK
                    logger.debug('\n RIPP CLIENT: ACK RECEIVED A:{}\n'.format(pkt.AckNo))
                    # Check ACK Number in Data Storage
                    # Cancel timer.
                    self.pktHdlr.check_ack(pkt)

                elif RIPPPacketType.FIN.value == pkt.Type:  # type FIN
                    logger.warning('\n RIPP CLIENT: FIN RECEIVED S:{}\n'.format(pkt.SeqNo))
                    self.state = StateType.CLOSING.value
                    # Process as data packet
                    self.pktHdlr.process_data(pkt)

                else:
                    logger.error('\n RIPP CLIENT: INVALID PACKET TYPE RECEIVED \n')

            elif self.state == StateType.SYN_SENT.value:
                # look for SYNACK for handshake
                ack = self.seqID + 1
                if RIPPPacketType.SYN.value in pkt.Type and \
                        RIPPPacketType.ACK.value in pkt.Type and pkt.AckNo == ack:
                    logger.debug('\n RIPP CLIENT: SYNACK RECEIVED S:{}, A:{}\n'.format(pkt.SeqNo, pkt.AckNo))
                    self.synTimer.cancel()
                    # Process SYNACK packet; Send ACK
                    ack_pkt = RIPPPacket().ack_packet(seq_no=pkt.AckNo, ack_no=pkt.SeqNo + 1)
                    self.transport.write(ack_pkt.__serialize__())
                    logger.debug(
                        '\n RIPP CLIENT RESPONDING WITH ACK S:{}, A:{} \n'.format(ack_pkt.SeqNo, ack_pkt.AckNo))
                    self.seqID = ack_pkt.SeqNo
                    self.establish_connection()

                else:
                    logger.debug('\n RIPP Client:  RECEIVED WRONG PACKET DURING HANDSHAKE. CLOSING\n')
                    self.transport.close()

            elif self.state == StateType.CLOSING.value:
                # If higherProtocol().con_lost() was called, no longer process data. Just send ACKs.
                # else continue handling data until FIN packet is processed in the data buffer.
                if self.finSent:  # If this protocol has sent a FIN request
                    if RIPPPacketType.DATA.value == pkt.Type:
                        # Send an ACK. Do not process packet.
                        data_ack = RIPPPacket().ack_packet(ack_no=pkt.SeqNo + len(pkt.Data))
                        self.transport.write(data_ack.__serialize__())
                    elif RIPPPacketType.ACK.value == pkt.Type:
                        self.pktHdlr.check_ack(pkt)
                        # Check for final ACK
                        if pkt.AckNo >= self.pktHdlr.finalACK:
                            self.shutdown()
                    elif RIPPPacketType.FIN.value == pkt.Type:
                        # Send a FIN ACK. Then shutdown.
                        fin_ack = RIPPPacket().ack_packet(ack_no=pkt.SeqNo + 1)
                        self.transport.write(fin_ack.__serialize__())
                        self.shutdown()
                else:  # In a CLOSING state by receiving a FIN request
                    if RIPPPacketType.DATA.value == pkt.Type:  # type Data
                        logger.debug('\n RIPP CLIENT CLOSING: RECEIVED DATA PACKET S:{} \n'.format(pkt.SeqNo))
                        # Process Data Packet and send ACK
                        self.pktHdlr.process_data(pkt)
                    elif RIPPPacketType.ACK.value == pkt.Type:  # type ACK
                        logger.debug('\n RIPP CLIENT CLOSING: ACK RECEIVED A:{}\n'.format(pkt.AckNo))
                        # Check ACK Number in Data Storage
                        # Cancel timer.
                        self.pktHdlr.check_ack(pkt)
                    elif RIPPPacketType.FIN.value == pkt.Type:  # type FIN
                        logger.debug('\n RIPP CLIENT CLOSING: FIN RECEIVED S:{}\n'.format(pkt.SeqNo))
                        # Process as data packet
                        self.pktHdlr.process_data(pkt)
                    else:
                        logger.error('\n RIPP CLIENT: INVALID PACKET TYPE RECEIVED \n')

            else:
                logger.warning('\n RIPP {} PROTOCOL IN BAD STATE\n'.format(self.ProtocolID))

    def connection_lost(self, exc):
        logger.error('\n RIPP CLIENT: Connection to server lost.\n')
        self.transport = None

    # ---------- Custom methods ---------------- #
    def initiate_handshake(self):
        # Make SYN packet to initiate session
        if self.state == StateType.LISTEN.value:
            syn_pkt = RIPPPacket().syn_packet(seq_no=self.seqID)
            logger.debug('\n RIPP CLIENT: SENDING SYN PACKET S:{}\n'.format(syn_pkt.SeqNo))
            self.transport.write(syn_pkt.__serialize__())
            self.state = StateType.SYN_SENT.value
            self.synTimer = asyncio.get_event_loop().call_later(0.1, self.resend_SYN, syn_pkt)

    def resend_SYN(self, syn):
        logger.debug('\n RIPP CLIENT: RESENDING SYN PACKET S:{}\n'.format(syn.SeqNo))
        self.transport.write(syn.__serialize__())
        # Restart timer
        self.synTimer = asyncio.get_event_loop().call_later(0.1, self.resend_SYN, syn)

    def establish_connection(self):
        # Make connection
        logger.debug('\n RIPP CLIENT MAKING CONNECTION \n')
        self.RippTransport = RippTransport(self)
        self.higherProtocol().connection_made(self.RippTransport)
        self.state = StateType.ESTABLISHED.value

    def shutdown(self):
        self.pktHdlr.cancelTimers()
        self.pktHdlr.ackTimers.clear()
        self.pktHdlr.sentDataPkts.clear()
        self.state = StateType.CLOSED.value
        self.transport.close()
