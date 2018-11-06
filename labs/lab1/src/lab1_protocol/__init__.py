from .RIPPServerProtocol import RippServerProtocol
from .RIPPClientProtocol import RippClientProtocol
from playground.network.common import StackingProtocolFactory
import playground

ripp_client = StackingProtocolFactory(lambda: RippClientProtocol())
ripp_server = StackingProtocolFactory(lambda: RippServerProtocol())
rippConnector = playground.Connector(protocolStack=(ripp_client, ripp_server))
playground.setConnector("lab1protocol", rippConnector)
