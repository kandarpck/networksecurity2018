from ..lab1protocol.RIPPServerProtocol import RippServerProtocol
from ..lab1protocol.RIPPClientProtocol import RippClientProtocol
from .SITHClientProtocol import SithClientProtocol
from .SITHServerProtocol import SithServerProtocol
from playground.network.common import StackingProtocolFactory
import playground

secure_client = StackingProtocolFactory(lambda: RippClientProtocol(), lambda: SithClientProtocol())
secure_server = StackingProtocolFactory(lambda: RippServerProtocol(), lambda: SithServerProtocol())
secureRippConnector = playground.Connector(protocolStack=(secure_client, secure_server))
playground.setConnector("secure_ripp", secureRippConnector)
