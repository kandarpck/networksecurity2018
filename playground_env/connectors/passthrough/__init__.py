import playground
from .passthrough import PassThroughClientProtocol, PassThroughServerProtocol

passthrough_connector = playground.Connector(protocolStack=(
    PassThroughClientProtocol,
    PassThroughServerProtocol))

playground.setConnector('passthrough', passthrough_connector)
