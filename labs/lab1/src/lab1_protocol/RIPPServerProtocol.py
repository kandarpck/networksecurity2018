from logging import getLogger, WARNING
from random import randint

from playground.network.common import StackingProtocol

from labs.lab1.src.lab1_protocol.PacketHandler import PacketHandler
from labs.lab1.src.lab1_protocol.RIPPPacket import RIPPPacket
from labs.lab1.src.lab1_protocol.RIPPPacketType import RIPPPacketType, StateType
from labs.lab1.src.lab1_protocol.RippTransport import RippTransport

logger = getLogger('playground.' + __name__)
logger.setLevel(WARNING)


class RippServerProtocol(StackingProtocol):
    def __init__(self):
        super(RippServerProtocol, self).__init__()
        self.ProtocolID = 'SERVER'
        self.RippTransport = None
        self.transport = None
        self.deserializer = RIPPPacket.Deserializer()
        self.pktHdlr = PacketHandler(self)
        self.state = StateType.LISTEN.value
        self.seqID = randint(0, 2 ** 32)
        self.ackID = 0
        self.finSent = False

    # ---------- Overridden methods ---------------- #

    def connection_made(self, transport):
        logger.debug('\n RIPP Server connection made with {}\n'.format(transport.get_extra_info('peername')))
        self.transport = transport

    def data_received(self, data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            logger.debug('\n RIPP Server: {} received \n'.format(pkt))

            if not pkt.validate(pkt):# not isinstance(pkt, RIPPPacket) and
                logger.error('\n RIPP SERVER: INVALID PACKET TYPE RECEIVED \n')
                continue
                #self.transport.close()

            elif self.state == StateType.ESTABLISHED.value:
                if RIPPPacketType.DATA.value.upper() in pkt.Type.upper():  # type Data
                    logger.debug('\n RIPP SERVER: RECEIVED DATA PACKET S:{} \n'.format(pkt.SeqNo))
                    # Process Data Packet and send ACK
                    self.pktHdlr.process_data(pkt)
                elif RIPPPacketType.ACK.value.upper() in pkt.Type.upper():  # type ACK
                    logger.debug('\n RIPP SERVER: ACK RECEIVED A:{}\n'.format(pkt.AckNo))
                    # Check ACK Number in Data Storage
                    # Cancel timer.
                    self.pktHdlr.check_ack(pkt)
                elif RIPPPacketType.FIN.value.upper() in pkt.Type.upper():  # type FIN
                    logger.warning('\n RIPP SERVER: FIN RECEIVED S:{}\n'.format(pkt.SeqNo))
                    self.state = StateType.CLOSING.value
                    # Process as data packet
                    self.pktHdlr.process_data(pkt)
                else:
                    logger.error('\n RIPP SERVER: INVALID PACKET TYPE RECEIVED \n')

            elif self.state == StateType.LISTEN.value:
                if RIPPPacketType.SYN.value.upper() in pkt.Type.upper():
                    self.initiate_handshake(pkt)
                else:
                    logger.error('\n RIPP SERVER: INCOMPATIBLE PACKET FOR HANDSHAKE. CLOSING\n')
                    print('\n Type: {} | Seq: {} \n'.format(pkt.Type, pkt.SeqNo))
                    self.transport.close()

            elif self.state == StateType.SYN_RECEIVED.value:
                if RIPPPacketType.ACK.value.upper() in pkt.Type.upper() and \
                        pkt.SeqNo == self.ackID and pkt.AckNo == self.seqID + 1:
                    self.establish_connection(pkt)
                else:
                    logger.error('\n RIPP SERVER: INCOMPATIBLE PACKET FOR HANDSHAKE. CLOSING\n')
                    print('\n Type: {} | Seq: {} \n'.format(pkt.Type, pkt.SeqNo))
                    self.transport.close()

            elif self.state == StateType.CLOSING.value:
                # If higherProtocol().con_lost() was called, no longer process data. Just send ACKs.
                # else continue handling data until FIN packet is processed in the data buffer.
                if self.finSent:  # If this protocol has sent a FIN request
                    if RIPPPacketType.DATA.value.upper() in pkt.Type.upper():
                        # Send an ACK. Do not process packet.
                        data_ack = RIPPPacket().ack_packet(ack_no=pkt.SeqNo + len(pkt.Data))
                        self.transport.write(data_ack.__serialize__())
                    elif RIPPPacketType.ACK.value.upper() in pkt.Type.upper():
                        self.pktHdlr.check_ack(pkt)
                        # Check for final ACK
                        if pkt.AckNo >= self.pktHdlr.finalACK:
                            self.shutdown()
                    elif RIPPPacketType.FIN.value.upper() in pkt.Type.upper():
                        # Send a FIN ACK. Then shutdown.
                        fin_ack = RIPPPacket().ack_packet(ack_no=pkt.SeqNo + 1)
                        self.transport.write(fin_ack.__serialize__())
                        self.shutdown()

                else:  # In a CLOSING state by receiving a FIN request
                    if RIPPPacketType.DATA.value.upper() in pkt.Type.upper():  # type Data
                        logger.debug('\n RIPP SERVER: RECEIVED DATA PACKET S:{} \n'.format(pkt.SeqNo))
                        # Process Data Packet and send ACK
                        self.pktHdlr.process_data(pkt)
                    elif RIPPPacketType.ACK.value.upper() in pkt.Type.upper():  # type ACK
                        logger.debug('\n RIPP SERVER: ACK RECEIVED A:{}\n'.format(pkt.AckNo))
                        # Check ACK Number in Data Storage
                        # Cancel timer.
                        self.pktHdlr.check_ack(pkt)
                    elif RIPPPacketType.FIN.value.upper() in pkt.Type.upper():  # type FIN
                        logger.debug('\n RIPP SERVER: FIN RECEIVED S:{}\n'.format(pkt.SeqNo))
                        # Process as data packet
                        self.pktHdlr.process_data(pkt)
                    else:
                        logger.error('\n RIPP SERVER: INVALID PACKET TYPE RECEIVED \n')

            else:
                logger.warning('\n RIPP {} PROTOCOL IN BAD STATE\n'.format(self.ProtocolID))

    def connection_lost(self, exc):
        logger.error('\n RIPP SERVER: Connection to client lost.\n')
        self.transport = None

    # ---------- Custom methods ---------------- #
    def initiate_handshake(self, syn):
        logger.debug('\n RIPP SERVER: SYN RECEIVED S:{}\n'.format(syn.SeqNo))
        syn_ack_pkt = RIPPPacket().syn_ack_packet(seq_no=self.seqID, ack_no=syn.SeqNo + 1)
        self.ackID = syn_ack_pkt.AckNo
        logger.debug('\n RIPP SERVER: RESPONDING WITH SYNACK S:{}, A:{}\n'.format(syn_ack_pkt.SeqNo,
                                                                                  syn_ack_pkt.AckNo))
        self.transport.write(syn_ack_pkt.__serialize__())
        self.state = StateType.SYN_RECEIVED.value

    def establish_connection(self, ack):
        logger.debug('\n RIPP SERVER: ACK RECEIVED S:{}, A:{}\n'.format(ack.SeqNo, ack.AckNo))
        # Make connection
        logger.debug('\n RIPP SERVER MAKING CONNECTION \n')
        self.RippTransport = RippTransport(self)
        self.higherProtocol().connection_made(self.RippTransport)
        self.state = StateType.ESTABLISHED.value

    def shutdown(self):
        self.pktHdlr.cancelTimers()
        self.pktHdlr.ackTimers.clear()
        self.pktHdlr.sentDataPkts.clear()
        self.state = StateType.CLOSED.value
        self.transport.close()
