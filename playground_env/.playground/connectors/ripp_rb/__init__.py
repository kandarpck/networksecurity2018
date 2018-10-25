import playground
from .ripp_rb import pt_client, pt_server

ripp_connector = playground.Connector(protocolStack=(
    pt_client,
    pt_server))

playground.setConnector('ripp_rb', ripp_connector)
