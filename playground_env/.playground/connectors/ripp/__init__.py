import playground
from .ripp import pt_client, pt_server

ripp_connector = playground.Connector(protocolStack=(
    pt_client,
    pt_server))

playground.setConnector('ripp', passthrough_connector)
