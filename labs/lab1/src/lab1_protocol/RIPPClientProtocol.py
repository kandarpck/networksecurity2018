import hashlib
from logging import getLogger, WARNING
from random import randint

from playground.network.common import StackingProtocol

from labs.lab1.src.lab1_protocol.PacketHandler import PacketHandler
from labs.lab1.src.lab1_protocol.RIPPPacket import RIPPPacket
from labs.lab1.src.lab1_protocol.RIPPPacketType import RIPPPacketType, StateType
from labs.lab1.src.lab1_protocol.lab1_protocol import RippTransport

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

    def connection_made(self, transport):
        logger.debug('\n Client connection made with {}\n'.format(transport.get_extra_info('peername')))
        self.transport = transport

        # Make SYN packet to initiate session
        if self.state == StateType.LISTEN.value:
            seq = self.seqID
            syn = RIPPPacket(Type='SYN', SeqNo=seq, AckNo=0, CRC=b"", Data=b"")
            logger.debug('\n RIPP CLIENT: SENDING SYN PACKET S:{}\n'.format(syn.SeqNo))
            self.transport.write(syn.__serialize__())
            self.state = StateType.SYN_SENT.value

    def data_received(self, data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            logger.debug('\n RIPP Client: {} received\n'.format(pkt))
            if not isinstance(pkt, RIPPPacket) and pkt.validate(pkt):
                logger.error('\n RIPP Client: INVALID PACKET TYPE RECEIVED \n')
                self.transport.close()

            elif self.state == StateType.ESTABLISHED.value:
                # Error-check

                if RIPPPacketType.DATA.value.upper() in pkt.Type.upper():  # type Data
                    logger.debug('\n RIPP CLIENT: RECEIVED DATA PACKET S:{} \n'.format(pkt.SeqNo))

                    # Process Data Packet and send ACK
                    self.pktHdlr.process_data(pkt)

                elif RIPPPacketType.ACK.value.upper() in pkt.Type.upper():  # type ACK
                    logger.debug('\n RIPP CLIENT: ACK RECEIVED A:{}\n'.format(pkt.AckNo))
                    # Check ACK Number in Data Storage
                    # Cancel timer.
                    self.pktHdlr.check_ack(pkt)

                elif RIPPPacketType.FIN.value.upper() in pkt.Type.upper():  # type FIN
                    logger.debug('\n RIPP CLIENT: FIN RECEIVED S:{}\n'.format(pkt.SeqNo))
                    self.state = StateType.CLOSING.value
                    # Process as data packet
                    self.pktHdlr.process_data(pkt)

                else:
                    logger.error('\n RIPP CLIENT: INVALID PACKET TYPE RECEIVED \n')

            elif self.state == StateType.SYN_SENT.value:
                # look for SYNACK for handshake
                ack = self.seqID + 1
                if RIPPPacketType.SYN.value.upper() in pkt.Type.upper() and \
                        RIPPPacketType.ACK.value.upper() in pkt.Type.upper() and pkt.AckNo == ack:
                    logger.debug('\n RIPP CLIENT: SYNACK RECEIVED S:{}, A:{}\n'.format(pkt.SeqNo, pkt.AckNo))
                    # Process SYNACK packet; Send ACK
                    ackPkt = RIPPPacket(Type='ACK', SeqNo=pkt.AckNo, AckNo=pkt.SeqNo + 1, CRC=b"", Data=b"")
                    logger.debug('\n RIPP CLIENT RESPONDING WITH ACK S:{}, A:{} \n'.format(ackPkt.SeqNo, ackPkt.AckNo))
                    self.transport.write(ackPkt.__serialize__())
                    self.seqID = ackPkt.SeqNo
                    # make connection
                    logger.debug('\n RIPP CLIENT MAKING CONNECTION \n')
                    self.RippTransport = RippTransport(self)
                    self.higherProtocol().connection_made(self.RippTransport)
                    self.state = StateType.ESTABLISHED.value
                else:
                    logger.debug('\n RIPP Client:  RECEIVED WRONG PACKET DURING HANDSHAKE. CLOSING\n')
                    self.transport.close()

            elif self.state == StateType.CLOSING.value:
                # If higherProtocol().con_lost() was called, no longer process data. Just send ACKs.
                # else continue handling data until FIN packet is processed in the data buffer.
                # Error Check
                if self.finSent:  # If this protocol has sent a FIN request
                    if RIPPPacketType.DATA.value.upper() in pkt.Type.upper():
                        # Send an ACK. Do not process packet.
                        dataAckNo = pkt.SeqNo + len(pkt.Data)
                        dataAck = RIPPPacket(Type='ACK', SeqNo=0, AckNo=dataAckNo, CRC=b'', Data=b'')
                        dataAck.CRC = hashlib.sha256(dataAck.__serialize__()).digest()
                        self.transport.write(dataAck.__serialize__())
                    elif RIPPPacketType.ACK.value.upper() in pkt.Type.upper():
                        self.pktHdlr.check_ack(pkt)
                        # Check for final ACK
                        if pkt.AckNo >= self.pktHdlr.finalACK:
                            self.pktHdlr.cancelTimers()
                            self.pktHdlr.ackTimers.clear()
                            self.pktHdlr.sentDataPkts.clear()
                            self.state = StateType.CLOSED.value
                            self.transport.close()
                    elif RIPPPacketType.FIN.value.upper() in pkt.Type.upper():
                        # Send a FIN ACK. Then shutdown.
                        finAck = RIPPPacket(Type='ACK', SeqNo=0, AckNo=pkt.SeqNo + 1, CRC=b'', Data=b'')
                        finAck.CRC = hashlib.sha256(finAck.__serialize__()).digest()
                        self.transport.write(finAck.__serialize__())
                        # Shutdown
                        self.pktHdlr.cancelTimers()
                        self.pktHdlr.ackTimers.clear()
                        self.pktHdlr.sentDataPkts.clear()
                        self.state = StateType.CLOSED.value
                        self.transport.close()
                else:  # In a CLOSING state by receiving a FIN request
                    if RIPPPacketType.DATA.value.upper() in pkt.Type.upper():  # type Data
                        logger.debug('\n RIPP CLIENT CLOSING: RECEIVED DATA PACKET S:{} \n'.format(pkt.SeqNo))
                        # Process Data Packet and send ACK
                        self.pktHdlr.process_data(pkt)
                    elif RIPPPacketType.ACK.value.upper() in pkt.Type.upper():  # type ACK
                        logger.debug('\n RIPP CLIENT CLOSING: ACK RECEIVED A:{}\n'.format(pkt.AckNo))
                        # Check ACK Number in Data Storage
                        # Cancel timer.
                        self.pktHdlr.check_ack(pkt)
                    elif RIPPPacketType.FIN.value.upper() in pkt.Type.upper():  # type FIN
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
