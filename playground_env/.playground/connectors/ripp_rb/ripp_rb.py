from labs.lab1.src.lab1_protocol.lab1_protocol import RippClientProtocol, RippServerProtocol
from playground.network.common import StackingProtocolFactory

pt_client = StackingProtocolFactory(lambda: RippClientProtocol())
pt_server = StackingProtocolFactory(lambda: RippServerProtocol())
