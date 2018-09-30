from labs.lab1.src.lab1_protocol import PassThroughClientProtocol, PassThroughServerProtocol
from playground.network.common import StackingProtocolFactory

pt_client = StackingProtocolFactory(lambda: PassThroughClientProtocol())
pt_server = StackingProtocolFactory(lambda: PassThroughServerProtocol())
