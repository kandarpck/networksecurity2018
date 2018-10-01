from labs.lab1.src.lab1_protocol.RIPPClientProtocol import RIPPClientProtocol
from labs.lab1.src.lab1_protocol.RIPPServerProtocol import RIPPServerProtocol
from playground.network.common import StackingProtocolFactory

pt_client = StackingProtocolFactory(lambda: RIPPClientProtocol())
pt_server = StackingProtocolFactory(lambda: RIPPServerProtocol())
