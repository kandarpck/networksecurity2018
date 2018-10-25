from labs.lab1.src.lab1_protocol.RIPPClientProtocol import RippClientProtocol
from labs.lab1.src.lab1_protocol.RIPPServerProtocol import RippServerProtocol

from playground.network.common import StackingProtocolFactory

pt_client = StackingProtocolFactory(lambda: RippClientProtocol())
pt_server = StackingProtocolFactory(lambda: RippServerProtocol())
