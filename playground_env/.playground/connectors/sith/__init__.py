import playground

from .sith import secure_server, secure_client

secureRippConnector = playground.Connector(protocolStack=(secure_client, secure_server))
playground.setConnector("sith", secureRippConnector)
