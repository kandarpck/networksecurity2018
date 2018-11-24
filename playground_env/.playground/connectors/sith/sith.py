from playground.network.common import StackingProtocolFactory

from labs.lab1.src.lab2_protocol.SITHClientProtocol import SithClientProtocol
from labs.lab1.src.lab2_protocol.SITHServerProtocol import SithServerProtocol
from labs.lab1.src.lab1_protocol.RIPPClientProtocol import RippClientProtocol
from labs.lab1.src.lab1_protocol.RIPPServerProtocol import RippServerProtocol

secure_client = StackingProtocolFactory(lambda: RippClientProtocol(), lambda: SithClientProtocol())
secure_server = StackingProtocolFactory(lambda: RippServerProtocol(), lambda: SithServerProtocol())
