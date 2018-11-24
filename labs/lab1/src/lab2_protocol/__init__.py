import playground
from playground.network.common import StackingProtocolFactory

from .SITHClientProtocol import SithClientProtocol
from .SITHServerProtocol import SithServerProtocol
from ..lab1_protocol.RIPPClientProtocol import RippClientProtocol
from ..lab1_protocol.RIPPServerProtocol import RippServerProtocol

secure_client = StackingProtocolFactory(lambda: RippClientProtocol(), lambda: SithClientProtocol())
secure_server = StackingProtocolFactory(lambda: RippServerProtocol(), lambda: SithServerProtocol())
secureRippConnector = playground.Connector(protocolStack=(secure_client, secure_server))
playground.setConnector("secure_ripp", secureRippConnector)
