import playground
from .passthrough import pt_client, pt_server

passthrough_connector = playground.Connector(protocolStack=(
    pt_client,
    pt_server))

playground.setConnector('passthrough', passthrough_connector)
