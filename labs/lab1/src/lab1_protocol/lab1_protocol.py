import asyncio
import hashlib
import logging
from random import randint

import playground
from playground.network.common import StackingProtocol, StackingTransport

from labs.lab1.src.lab1_protocol.RIPPPacket import RIPPPacket
from labs.lab1.src.lab1_protocol.RIPPPacketType import RIPPPacketType, StateType

logger = logging.getLogger('playground.' + __name__)
logger.setLevel(logging.WARNING)


class RippServerProtocol(StackingProtocol):
    def __init__(self):
        self.ProtocolID = 'SERVER'
        self.RippTransport = None
        self.transport = None
        self.deserializer = RIPPPacket.Deserializer()
        self.pktHdlr = PacketHandler(self)
        self.state = StateType.LISTEN.value
        self.seqID = randint(0, 2 ** 32)
        self.ackID = 0
        self.finSent = False

    def connection_made(self, transport):
        logger.debug('\n RIPP Server connection made with {}\n'.format(transport.get_extra_info('peername')))
        self.transport = transport

    def data_received(self, data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            logger.debug('\n RIPP Server: {} received\n'.format(pkt))

            if self.state == StateType.LISTEN.value:
                # Handshake Initiated
                if RIPPPacketType.SYN.value.lower() in pkt.Type.lower():
                    logger.debug('\n RIPP SERVER: SYN RECEIVED S:{}\n'.format(pkt.SeqNo))
                    seq = self.seqID
                    synackPkt = RIPPPacket(Type='SYNACK', SeqNo=seq, AckNo=pkt.SeqNo + 1, CRC=b"", Data=b"")
                    self.ackID = synackPkt.AckNo
                    logger.debug(
                        '\n RIPP SERVER: RESPONDING WITH SYNACK S:{}, A:{}\n'.format(synackPkt.SeqNo, synackPkt.AckNo))
                    self.transport.write(synackPkt.__serialize__())
                    self.state = StateType.SYN_RECEIVED.value
                else:
                    logger.debug('\n RIPP SERVER: INCOMPATIBLE PACKET FOR HANDSHAKE. CLOSING\n')
                    self.transport.close()

            elif self.state == StateType.SYN_RECEIVED.value:
                # Complete handshake
                if RIPPPacketType.ACK.value.lower() in pkt.Type.lower() and pkt.SeqNo == self.ackID and pkt.AckNo == self.seqID + 1:
                    # Check ACK
                    logger.debug('\n RIPP SERVER: ACK RECEIVED S:{}, A:{}\n'.format(pkt.SeqNo, pkt.AckNo))
                    # Make connection
                    logger.debug('\n RIPP SERVER MAKING CONNECTION \n')
                    self.RippTransport = RippTransport(self)
                    self.higherProtocol().connection_made(self.RippTransport)
                    self.state = StateType.ESTABLISHED.value
                else:
                    logger.debug('\n RIPP SERVER: INCOMPATIBLE PACKET FOR HANDSHAKE. CLOSING\n')
                    self.transport.close()

            elif self.state == StateType.ESTABLISHED.value:
                # Error-check
                if self.pktHdlr.checkHash(pkt) == True:

                    if RIPPPacketType.DATA.value.lower() in pkt.Type.lower():  # type Data
                        logger.debug('\n RIPP SERVER: RECEIVED DATA PACKET S:{} \n'.format(pkt.SeqNo))
                        # Process Data Packet and send ACK
                        self.pktHdlr.processData(pkt)

                    elif RIPPPacketType.ACK.value.lower() in pkt.Type.lower():  # type ACK
                        logger.debug('\n RIPP SERVER: ACK RECEIVED A:{}\n'.format(pkt.AckNo))
                        # Check ACK Number in Data Storage
                        # Cancel timer.
                        self.pktHdlr.checkAck(pkt)

                    elif RIPPPacketType.FIN.value.lower() in pkt.Type.lower():  # type FIN
                        logger.debug('\n RIPP SERVER: FIN RECEIVED S:{}\n'.format(pkt.SeqNo))
                        self.state = StateType.CLOSING.value
                        # Process as data packet
                        self.pktHdlr.processData(pkt)

                    else:
                        logger.debug('\n RIPP SERVER: INVALID PACKET TYPE RECEIVED \n')
                elif self.pktHdlr.checkHash(pkt) == False:
                    logger.debug('\n RIPP SERVER: CRC CHECK FAIL. DROPPING PACKET S:{}\n'.format(pkt.SeqNo))
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
                            logger.debug('\n RIPP SERVER: RECEIVED DATA PACKET S:{} \n'.format(pkt.SeqNo))
                            # Process Data Packet and send ACK
                            self.pktHdlr.processData(pkt)
                        elif RIPPPacketType.ACK.value.lower() in pkt.Type.lower():  # type ACK
                            logger.debug('\n RIPP SERVER: ACK RECEIVED A:{}\n'.format(pkt.AckNo))
                            # Check ACK Number in Data Storage
                            # Cancel timer.
                            self.pktHdlr.checkAck(pkt)
                        elif RIPPPacketType.FIN.value.lower() in pkt.Type.lower():  # type FIN
                            logger.debug('\n RIPP SERVER: FIN RECEIVED S:{}\n'.format(pkt.SeqNo))
                            # Process as data packet
                            self.pktHdlr.processData(pkt)
                        else:
                            logger.debug('\n RIPP SERVER: INVALID PACKET TYPE RECEIVED \n')
                else:
                    logger.debug('\n RIPP SERVER: CRC CHECK FAIL. DROPPING PACKET S:{}\n'.format(pkt.SeqNo))
                    continue  # if hashes do not match do nothing with pkt.
            else:
                logger.debug('\n RIPP {} PROTOCOL IN BAD STATE\n'.format(self.ProtocolID))

    def connection_lost(self, exc):
        logger.debug('\n RIPP SERVER: Connection to client lost.\n')
        self.transport = None


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
                        logger.debug('\n RIPP CLIENT: INVALID PACKET TYPE RECEIVED \n')
                else:
                    logger.debug('\n RIPP CLIENT: CRC CHECK FAIL. DROPPING PACKET S:{}\n'.format(pkt.SeqNo))
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
                            logger.debug('\n RIPP CLIENT: INVALID PACKET TYPE RECEIVED \n')
                else:
                    logger.debug('\n RIPP CLIENT: CRC CHECK FAIL. DROPPING PACKET S:{}\n'.format(pkt.SeqNo))
                    continue  # if hashes do not match do nothing with pkt.
            else:
                logger.debug('\n RIPP {} PROTOCOL IN BAD STATE\n'.format(self.ProtocolID))

    def connection_lost(self, exc):
        logger.debug('\n RIPP CLIENT: Connection to server lost.\n')
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
                    logger.debug('\n RIPP {}: Transporting RIPP Packet S:{}\n'.format(self.Protocol.ProtocolID, pkt.SeqNo))
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


# PacketHandler will store sent packets for each protocol.  It will also handle
# comparing hashes for error checking, handle timers for ACKs and resends.
class PacketHandler:
    def __init__(self, protocol):
        self.Protocol = protocol
        self.dataBuffer = []
        self.backlog = []
        self.sentDataPkts = []
        self.ackTimers = {}
        self.nextSeqNo = 0
        self.ackTotal = 0
        self.finalACK = 0
        self.timeout = None

    def storePkt(self, packet):
        # Store sent packets in order by SeqNo.
        if packet not in self.sentDataPkts:
            self.sentDataPkts.append(packet)
            self.sentDataPkts.sort(key=lambda x: x.SeqNo, reverse=False)

        # Start timer for stored packet. Stored as key:value pairs (SeqNo:timer)
        timer = asyncio.get_event_loop().call_later(0.3, self.resend, packet)
        self.ackTimers.update({packet.SeqNo: timer})

    # Set up timer to send up a single packet. Must be less than ACK Timers
    def addToBuffer(self, packet):
        # Check for FIN packets.  Send Final ACK. ClearBuffer. Close Tranport.
        if packet.Type == 'FIN':
            self.ackTotal = packet.SeqNo + 1
            self.nextSeqNo = packet.SeqNo + 1
            self.dataBuffer.append(packet)

            self.sendACK()
            self.clearBuffer()
        else:
            self.ackTotal = packet.SeqNo + len(packet.Data)
            self.nextSeqNo = packet.SeqNo + len(packet.Data)
            self.dataBuffer.append(packet)

        # Check backlog for self.nextSeqNo.
        if len(self.backlog) > 0:
            index = 0
            while index < len(self.backlog):
                pkt = self.backlog[index]
                if pkt.SeqNo == self.nextSeqNo:
                    if len(self.dataBuffer) == 16:
                        logger.debug('\n RIPP {}:  Data Buffer Maxed.\n'.format(self.Protocol.ProtocolID))
                        self.sendACK()
                        self.clearBuffer()
                    elif pkt.Type == 'FIN':
                        self.ackTotal = pkt.SeqNo + 1
                        self.nextSeqNo = pkt.SeqNo + 1
                        self.dataBuffer.append(pkt)
                        self.sendAck()
                        self.clearBuffer()
                        index += 1
                        break
                    else:
                        self.nextSeqNo = pkt.SeqNo + len(pkt.Data)
                        self.ackTotal = pkt.SeqNo + len(pkt.Data)
                        self.dataBuffer.append(pkt)
                        self.backlog.pop(index)
                        index = 0  # restart while loop
                else:
                    index += 1

        # Check size of buffer
        if len(self.dataBuffer) == 16:
            logger.debug('\n RIPP {}:  Data Buffer Maxed.\n'.format(self.Protocol.ProtocolID))
            self.sendACK()
            self.clearBuffer()

        # Sort Buffers
        self.dataBuffer.sort(key=lambda x: x.SeqNo, reverse=False)
        self.backlog.sort(key=lambda x: x.SeqNo, reverse=False)
        # start Timeout timer.  When it reaches zero, clear buffer.  timeout < resend
        self.timeout = asyncio.get_event_loop().call_later(0.2, self.Timeout)

    def cleanBacklog(self):
        # Deletes all packets with seqNO that are < the current ack total.
        # Implying that these packets would just be redundant data.
        tempList = []
        for pkt in self.backlog:
            if pkt.SeqNo >= self.ackTotal:
                tempList.append(pkt)
            else:
                continue
        self.backlog = tempList

    def clearBuffer(self):
        # Cancel timer
        self.timeout.cancel()
        self.dataBuffer.sort(key=lambda x: x.SeqNo, reverse=False)  # make sure Buffer is sorted

        logger.debug('\n RIPP {}: CLEARING DATA BUFFER. SENDING DATA TO HIGHER PROTOCOL.\n'.format(self.Protocol.ProtocolID))

        # Add check for FIN packet type. Call higherProtocol().connection_lost(None)
        for pkt in self.dataBuffer:
            if pkt.Type == 'FIN':
                self.Protocol.higherProtocol().connection_lost(None)
                self.Protocol.transport.close()
                self.backlog.clear()
                self.dataBuffer.clear()
                self.Protocol.state = StateType.CLOSED.value
                break
            else:
                stripData = pkt.Data
                self.Protocol.higherProtocol().data_received(stripData)

        # Clear buffer
        self.dataBuffer.clear()

    def sendACK(self):
        # Send ACK for data in buffer
        ackPkt = RIPPPacket(Type='ACK', SeqNo=0, AckNo=self.ackTotal, CRC=b'', Data=b'')
        ackPkt.CRC = hashlib.sha256(ackPkt.__serialize__()).digest()
        logger.debug('\n RIPP {} Transport: SENDING ACK A:{}\n'.format(self.Protocol.ProtocolID, self.ackTotal))
        self.Protocol.transport.write(ackPkt.__serialize__())

        # Clean backlog of excess packets with SeqNo < ackTotal
        self.cleanBacklog()

    def checkAck(self, packet):
        # When ack is received cancel all timers with SeqNo < AckNo.
        tempList = []
        for pkt in self.sentDataPkts:
            if pkt.SeqNo < packet.AckNo:
                if pkt.SeqNo in self.ackTimers:
                    # cancel timer
                    timer = self.ackTimers[pkt.SeqNo]
                    timer.cancel()
                    tempList.append(pkt)
                else:
                    continue
            else:
                break

        if len(tempList) > 0:
            for pkt in tempList:
                # del ack entry
                del self.ackTimers[pkt.SeqNo]
                self.sentDataPkts.remove(pkt)

    def resend(self, packet):
        logger.debug('\n RIPP {}: RESENDING PACKET S:{}\n'.format(self.Protocol.ProtocolID, packet.SeqNo))
        self.storePkt(packet)  # reset ACK timer
        self.Protocol.transport.write(packet.__serialize__())

    def checkHash(self, packet):
        hash = packet.CRC
        packet.CRC = b""
        rehash = hashlib.sha256(packet.__serialize__()).digest()
        if hash == rehash:
            return True
        else:
            return False

    def processData(self, pkt):
        # Build dataBuffer with subsequent packets.  Send a single 'total' ACK
        # for all packets received.  If packet received out of order, build
        # backlog, wait for proper packet.
        if self.nextSeqNo == 0:  # 1st packet or expected next packet
            self.addToBuffer(pkt)
        elif pkt.SeqNo == self.nextSeqNo:  # expected next packet
            self.timeout.cancel()
            self.addToBuffer(pkt)
        else:  # Wrong SeqNo Received
            self.timeout.cancel()
            logger.debug('\n RIPP {}: RECEIVED UNEXPECTED PACKET S:{}\n'.format(self.Protocol.ProtocolID, pkt.SeqNo))

            # Clear buffer and ACK
            if len(self.dataBuffer) > 0:
                self.sendACK()
                self.clearBuffer()

            # Add pkt to backlog
            if pkt not in self.backlog:
                logger.debug('\n RIPP {}: ADDING TO BACKLOG S:{}\n'.format(self.Protocol.ProtocolID, pkt.SeqNo))
                self.backlog.append(pkt)
                self.backlog.sort(key=lambda x: x.SeqNo, reverse=False)

    def sendFIN(self, seqno):
        # Cancel all data buffers and timers
        self.timeout.cancel()
        self.dataBuffer.clear()
        self.backlog.clear()

        finPkt = RIPPPacket(Type='FIN', SeqNo=seqno, AckNo=0, CRC=b'', Data=b'')
        finPkt.CRC = hashlib.sha256(finPkt.__serialize__()).digest()
        self.storePkt(finPkt)
        self.Protocol.transport.write(finPkt.__serialize__())

        self.finalACK = seqno + 1
        self.Protocol.finSent = True

    def cancelTimers(self):
        # Cancel all ACK Timers
        for key in self.ackTimers:
            self.ackTimers[key].cancel()

    def Timeout(self):
        # Data has not been received within timeout window.
        logger.debug('\n RIPP {}: TIMEOUT REACHED.  PUSHING DATA \n'.format(self.Protocol.ProtocolID))
        self.sendACK()
        self.clearBuffer()


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
