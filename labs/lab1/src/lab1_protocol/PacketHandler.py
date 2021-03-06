import asyncio
import bisect
import logging

from .RIPPPacket import RIPPPacket
from .RIPPPacketType import RIPPPacketType, StateType

logger = logging.getLogger('playground.' + __name__)
logger.setLevel(logging.WARNING)


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

    def store_packet(self, pkt):
        # Store sent packets in order by SeqNo.
        if pkt not in self.sentDataPkts:
            bisect.insort(self.sentDataPkts, pkt)

        # Start timer for stored packet. Stored as key:value pairs (SeqNo:timer)
        timer = asyncio.get_event_loop().call_later(1, self.resend, pkt)
        self.ackTimers.update({pkt.SeqNo: timer})

    # Set up timer to send up a single packet. Must be less than ACK Timers
    def addToBuffer(self, packet):
        # Check for FIN packets.  Send Final ACK. ClearBuffer. Close Tranport.
        if packet.Type == RIPPPacketType.FIN.value:
            self.ackTotal = packet.SeqNo + 1
            self.nextSeqNo = packet.SeqNo + 1
            bisect.insort(self.dataBuffer, packet)

            # start Timeout timer.  When it reaches zero, clear buffer.  timeout < resend
            self.timeout = asyncio.get_event_loop().call_later(0.3, self.Timeout)

            self.sendACK()
            self.clearBuffer()
        else:
            self.ackTotal = packet.SeqNo + len(packet.Data)
            self.nextSeqNo = packet.SeqNo + len(packet.Data)
            bisect.insort(self.dataBuffer, packet)

            self.timeout = asyncio.get_event_loop().call_later(0.3, self.Timeout)

        # Check backlog for self.nextSeqNo.
        if self.backlog:
            index = 0
            while index < len(self.backlog):
                pkt = self.backlog[index]
                if pkt.SeqNo == self.nextSeqNo:
                    if len(self.dataBuffer) >= 100:
                        logger.warning('\n RIPP {}:  Data Buffer Maxed.\n'.format(self.Protocol.ProtocolID))
                        self.sendACK()
                        self.clearBuffer()
                    elif pkt.Type == RIPPPacketType.FIN.value:
                        self.ackTotal = pkt.SeqNo + 1
                        self.nextSeqNo = pkt.SeqNo + 1
                        self.dataBuffer.append(pkt)
                        # self.timeout = asyncio.get_event_loop().call_later(0.2, self.Timeout)
                        self.sendACK()
                        self.clearBuffer()
                        index += 1
                        break
                    else:
                        self.nextSeqNo = pkt.SeqNo + len(pkt.Data)
                        self.ackTotal = pkt.SeqNo + len(pkt.Data)
                        self.dataBuffer.append(pkt)
                        self.timeout = asyncio.get_event_loop().call_later(0.3, self.Timeout)
                        self.backlog.pop(index)
                        index = 0  # restart while loop
                else:
                    index += 1

        # Check size of buffer
        if len(self.dataBuffer) >= 100:
            logger.warning('\n RIPP {}: Data Buffer Maxed.\n'.format(self.Protocol.ProtocolID))
            self.sendACK()
            self.clearBuffer()

    def cleanBacklog(self):
        # Deletes all packets with seqNO that are < the current ack total.
        # Implying that these packets would just be redundant data.
        i = bisect.bisect_right(self.backlog, RIPPPacket().syn_packet(seq_no=self.ackTotal))
        self.backlog = self.backlog[i - 1:] if i else self.backlog

    def clearBuffer(self):
        # Cancel timer
        self.timeout.cancel()
        # self.dataBuffer.sort(key=lambda x: x.SeqNo, reverse=False)  # make sure Buffer is sorted

        logger.warning(
            '\n RIPP {}: CLEARING DATA BUFFER. SENDING DATA TO HIGHER PROTOCOL.\n'.format(self.Protocol.ProtocolID))

        # Add check for FIN packet type. Call higherProtocol().connection_lost(None)
        for pkt in self.dataBuffer:
            if pkt.Type == RIPPPacketType.FIN.value:
                self.cancelTimers()
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
        ack_pkt = RIPPPacket().ack_packet(ack_no=self.ackTotal)
        logger.debug('\n RIPP {} Transport: SENDING ACK A:{}\n'.format(self.Protocol.ProtocolID, self.ackTotal))
        self.Protocol.transport.write(ack_pkt.__serialize__())

        # Clean backlog of excess packets with SeqNo < ackTotal
        self.cleanBacklog()

    def check_ack(self, packet):
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

        for pkt in tempList:
            # del ack entry
            del self.ackTimers[pkt.SeqNo]
            self.sentDataPkts.remove(pkt)

    def resend(self, packet):
        logger.debug('\n RIPP {}: RESENDING PACKET S:{}\n'.format(self.Protocol.ProtocolID, packet.SeqNo))
        self.store_packet(packet)  # reset ACK timer
        self.Protocol.transport.write(packet.__serialize__())

    def process_data(self, pkt):
        # Build dataBuffer with subsequent packets.  Send a single 'total' ACK
        # for all packets received.  If packet received out of order, build
        # backlog, wait for proper packet.
        if not self.nextSeqNo:  # 1st packet or expected next packet
            self.addToBuffer(pkt)
        elif pkt.SeqNo == self.nextSeqNo:  # expected next packet
            self.timeout.cancel()
            self.addToBuffer(pkt)
        else:  # Wrong SeqNo Received
            self.timeout.cancel()
            logger.error('\n RIPP {}: RECEIVED UNEXPECTED PACKET S:{}\n'.format(self.Protocol.ProtocolID, pkt.SeqNo))

            # Clear buffer and ACK
            if self.dataBuffer:
                self.sendACK()
                self.clearBuffer()

            # Add pkt to backlog
            if pkt not in self.backlog:
                logger.debug('\n RIPP {}: ADDING TO BACKLOG S:{}\n'.format(self.Protocol.ProtocolID, pkt.SeqNo))
                bisect.insort(self.backlog, pkt)

    def sendFIN(self, seqno):
        # Cancel all data buffers and timers
        self.timeout.cancel()
        self.dataBuffer.clear()
        self.backlog.clear()

        fin_pkt = RIPPPacket().fin_packet(seq_no=seqno)
        self.store_packet(fin_pkt)
        self.Protocol.transport.write(fin_pkt.__serialize__())

        self.finalACK = seqno + 1
        self.Protocol.finSent = True

    def cancelTimers(self):
        self.timeout.cancel()
        # Cancel all ACK Timers
        for key in self.ackTimers:
            self.ackTimers[key].cancel()

    def Timeout(self):
        # Data has not been received within timeout window.
        logger.warning('\n RIPP {}: TIMEOUT REACHED.  PUSHING DATA \n'.format(self.Protocol.ProtocolID))
        self.sendACK()
        self.clearBuffer()
