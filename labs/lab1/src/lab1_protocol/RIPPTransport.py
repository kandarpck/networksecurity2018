import logging

from playground.network.common import StackingTransport

from labs.lab1.src.lab1_protocol.RIPPPacket import RIPPPacket
from labs.lab1.src.lab1_protocol.RIPPPacketType import StateType

logger = logging.getLogger('playground.' + __name__)
logger.setLevel(logging.WARNING)


class RippTransport(StackingTransport):
    # Store all sent data packets in protocol's pktHdlr
    # Add timer for all data packets sent
    def __init__(self, lower_protocol):
        self.Protocol = lower_protocol
        super().__init__(lower_protocol.transport)

    def write(self, data):
        MTU = 1500

        # MTU is 1500; Window size set to 16
        window = []
        Seq = self.Protocol.seqID

        while data:
            # Handle data in 1500 (MTU) sized chunks
            chunk, data = data[:MTU], data[MTU:]

            # Create and process Ripp Packet
            data_pkt = RIPPPacket().data_packet(seq_no=Seq, data_content=chunk)
            # Place in queue
            window.append(data_pkt)
            Seq += len(data_pkt.Data)
            self.Protocol.seqID = Seq

            if len(window) >= 100:  # Empty queue when max window size is reached
                logger.debug('\n RIPP {} Transport: Emptying Full Window \n'.format(self.Protocol.ProtocolID))
                for pkt in window:
                    logger.debug(
                        '\n RIPP {}: Transporting RIPP Packet S:{}\n'.format(self.Protocol.ProtocolID, pkt.SeqNo))
                    self.Protocol.pktHdlr.store_packet(pkt)  # store sent pkt
                    self.lowerTransport().write(pkt.__serialize__())
                # Clear queue
                window.clear()

        # Empty remaining queue after while loop
        if window:
            logger.debug('\n RIPP {} Transport: Clearing Window of final packets\n'.format(self.Protocol.ProtocolID))
            for pkt in window:
                logger.debug('\n RIPP {}: Transporting RIPP Packet S:{}\n'.format(self.Protocol.ProtocolID, pkt.SeqNo))
                self.Protocol.pktHdlr.store_packet(pkt)  # store sent pkt
                self.lowerTransport().write(pkt.__serialize__())
            # Clear queue
            window.clear()

    def close(self):
        # Application is no longer expecting to receive data.
        # Call protocol's protocol.connection_lost() method with None as argument.
        logger.warning(
            "\n RIPP {} Transport: close() Initiated.  Sending FIN packet and calling current protocol's connection_lost(None) \n".format(
                self.Protocol.ProtocolID))

        self.Protocol.higherProtocol().connection_lost(None)

        if self.Protocol.state == StateType.CLOSING.value:
            # Shutdown if protocol is already in a CLOSING state
            self.Protocol.pktHdlr.cancelTimers()
            self.Protocol.pktHdlr.sentDataPkts.clear()
            self.Protocol.pktHdlr.ackTimers.clear()
            self.Protocol.pktHdlr.dataBuffer.clear()
            self.Protocol.pktHdlr.backlog.clear()
            self.Protocol.transport.close()
            self.Protocol.state = StateType.CLOSED.value
        else:
            # Send FIN through PacketHandler to also delete data buffers
            self.Protocol.pktHdlr.sendFIN(self.Protocol.seqID)
            self.Protocol.state = StateType.CLOSING.value
