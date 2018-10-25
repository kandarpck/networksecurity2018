import asyncio
import hashlib
import logging
from random import randint

import playground
from playground.network.common import StackingProtocol, StackingTransport

from labs.lab1.src.lab1_protocol.PacketHandler import PacketHandler

from labs.lab1.src.lab1_protocol.RIPPPacket import RIPPPacket
from labs.lab1.src.lab1_protocol.RIPPPacketType import RIPPPacketType, StateType

logger = logging.getLogger('playground.' + __name__)
logger.setLevel(logging.WARNING)


class RippClientProtocol(StackingProtocol):
    def __init__(self):
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

            if self.state == StateType.SYN_SENT.value:
                # look for SYNACK for handshake
                ack = self.seqID + 1
                if RIPPPacketType.SYN.value.lower() in pkt.Type.lower() and RIPPPacketType.ACK.value.lower() in pkt.Type.lower() and pkt.AckNo == ack:
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

            elif self.state == StateType.ESTABLISHED.value:
                # Error-check
                if self.pktHdlr.checkHash(pkt) == True:

                    if RIPPPacketType.DATA.value.lower() in pkt.Type.lower():  # type Data
                        logger.debug('\n RIPP CLIENT: RECEIVED DATA PACKET S:{} \n'.format(pkt.SeqNo))

                        # Process Data Packet and send ACK
                        self.pktHdlr.processData(pkt)

                    elif RIPPPacketType.ACK.value.lower() in pkt.Type.lower():  # type ACK
                        logger.debug('\n RIPP CLIENT: ACK RECEIVED A:{}\n'.format(pkt.AckNo))
                        # Check ACK Number in Data Storage
                        # Cancel timer.
                        self.pktHdlr.checkAck(pkt)

                    elif RIPPPacketType.FIN.value.lower() in pkt.Type.lower():  # type FIN
                        logger.debug('\n RIPP CLIENT: FIN RECEIVED S:{}\n'.format(pkt.SeqNo))
                        self.state = StateType.CLOSING.value
                        # Process as data packet
                        self.pktHdlr.processData(pkt)

                    else:
                        logger.error('\n RIPP CLIENT: INVALID PACKET TYPE RECEIVED \n')
                else:
                    logger.error('\n RIPP CLIENT: CRC CHECK FAIL. DROPPING PACKET S:{}\n'.format(pkt.SeqNo))
                    continue  # if hashes do not match do nothing with pkt.

            elif self.state == StateType.CLOSING.value:
                # If higherProtocol().con_lost() was called, no longer process data. Just send ACKs.
                # else continue handling data until FIN packet is processed in the data buffer.
                # Error Check
                if self.pktHdlr.checkHash(pkt) == True:
                    if self.finSent == True:  # If this protocol has sent a FIN request
                        if RIPPPacketType.DATA.value.lower() in pkt.Type.lower():
                            # Send an ACK. Do not process packet.
                            dataAckNo = pkt.SeqNo + len(pkt.Data)
                            dataAck = RIPPPacket(Type='ACK', SeqNo=0, AckNo=dataAckNo, CRC=b'', Data=b'')
                            dataAck.CRC = hashlib.sha256(dataAck.__serialize__()).digest()
                            self.transport.write(dataAck.__serialize__())
                        elif RIPPPacketType.ACK.value.lower() in pkt.Type.lower():
                            self.pktHdlr.checkAck(pkt)
                            # Check for final ACK
                            if pkt.AckNo >= self.pktHdlr.finalACK:
                                self.pktHdlr.cancelTimers()
                                self.pktHdlr.ackTimers.clear()
                                self.pktHdlr.sentDataPkts.clear()
                                self.state = StateType.CLOSED.value
                                self.transport.close()
                        elif RIPPPacketType.FIN.value.lower() in pkt.Type.lower():
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
                        if RIPPPacketType.DATA.value.lower() in pkt.Type.lower():  # type Data
                            logger.debug('\n RIPP CLIENT CLOSING: RECEIVED DATA PACKET S:{} \n'.format(pkt.SeqNo))
                            # Process Data Packet and send ACK
                            self.pktHdlr.processData(pkt)
                        elif RIPPPacketType.ACK.value.lower() in pkt.Type.lower():  # type ACK
                            logger.debug('\n RIPP CLIENT CLOSING: ACK RECEIVED A:{}\n'.format(pkt.AckNo))
                            # Check ACK Number in Data Storage
                            # Cancel timer.
                            self.pktHdlr.checkAck(pkt)
                        elif RIPPPacketType.FIN.value.lower() in pkt.Type.lower():  # type FIN
                            logger.debug('\n RIPP CLIENT CLOSING: FIN RECEIVED S:{}\n'.format(pkt.SeqNo))
                            # Process as data packet
                            self.pktHdlr.processData(pkt)
                        else:
                            logger.error('\n RIPP CLIENT: INVALID PACKET TYPE RECEIVED \n')
                else:
                    logger.error('\n RIPP CLIENT: CRC CHECK FAIL. DROPPING PACKET S:{}\n'.format(pkt.SeqNo))
                    continue  # if hashes do not match do nothing with pkt.
            else:
                logger.warning('\n RIPP {} PROTOCOL IN BAD STATE\n'.format(self.ProtocolID))

    def connection_lost(self, exc):
        logger.error('\n RIPP CLIENT: Connection to server lost.\n')
        self.transport = None


class RippTransport(StackingTransport):
    # Store all sent data packets in protocol's pktHdlr
    # Add timer for all data packets sent
    def __init__(self, Protocol):
        self.Protocol = Protocol
        super().__init__(Protocol.transport)

    def write(self, data):
        MTU = 1500

        # MTU is 1500; Window size set to 16
        window = []
        Seq = self.Protocol.seqID

        while len(data) > 0:
            # Handle data in 1500 (MTU) sized chunks
            chunk, data = data[:MTU], data[MTU:]

            # Create and process Ripp Packet
            rPkt = RIPPPacket(Type='Data', SeqNo=Seq, AckNo=0, CRC=b"", Data=chunk)
            rPkt.CRC = hashlib.sha256(rPkt.__serialize__()).digest()
            # Place in queue
            window.append(rPkt)
            Seq += len(rPkt.Data)
            self.Protocol.seqID = Seq

            if len(window) == 16:  # Empty queue when max window size is reached
                logger.debug('\n RIPP {} Transport: Emptying Full Window \n'.format(self.Protocol.ProtocolID))
                for pkt in window:
                    logger.debug(
                        '\n RIPP {}: Transporting RIPP Packet S:{}\n'.format(self.Protocol.ProtocolID, pkt.SeqNo))
                    self.Protocol.pktHdlr.storePkt(pkt)  # store sent pkt
                    self.lowerTransport().write(pkt.__serialize__())
                # Clear queue
                window.clear()

        # Empty remaining queue after while loop
        if len(window) > 0:
            logger.debug('\n RIPP {} Transport: Clearing Window of final packets\n'.format(self.Protocol.ProtocolID))
            for pkt in window:
                logger.debug('\n RIPP {}: Transporting RIPP Packet S:{}\n'.format(self.Protocol.ProtocolID, pkt.SeqNo))
                self.Protocol.pktHdlr.storePkt(pkt)  # store sent pkt
                self.lowerTransport().write(pkt.__serialize__())
            # Clear queue
            window.clear()

    def close(self):
        # Application is no longer expecting to receive data.
        # Call protocol's protocol.connection_lost() method with None as argument.
        logger.debug(
            "\n RIPP {} Transport: close() Initiated.  Sending FIN packet and calling current protocol's connection_lost(None) \n".format(
                self.Protocol.ProtocolID))

        self.Protocol.higherProtocol().connection_lost(None)

        # Send FIN through PacketHandler to also delete data buffers
        self.Protocol.pktHdlr.sendFIN(self.Protocol.seqID)
        self.Protocol.state = StateType.CLOSING.value


# class ProtocolState:
# LISTEN - represents waiting for a connection request from any remote TCP and property
# SYN-SENT - waiting for a matching connection request after having sent a request
# SYN-RECEIVED - waiting for a confirming connection request ACK after having both received and sent a conn request.
# ESTABLISHED - represents an open connection.  Data transfer.
# CLOSING - Closing connection after receiving a FIN request.
# def __init__(self, state):
#    self.currentState = state

# def getState():
#    return self.currentState

# def setState(self, state):
#    self.currentState = state

async def main():
    loop = asyncio.get_event_loop()
    coro = playground.getConnector('lab1protocol').create_playground_server(lambda: RippServerProtocol(), port=9876)
    server = loop.run_until_complete(coro)
    loop.run_forever()
    loop.close()
