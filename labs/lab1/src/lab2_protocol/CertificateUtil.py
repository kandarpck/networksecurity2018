class CertificateUtils(object):

    def get_root_certificate(self):
        pass

    def get_certificates_for_ip(self, ip_addr):
        return None, None


class ClientCertificateUtils(CertificateUtils):
    def __init__(self, ip_addr):
        super(ClientCertificateUtils, self).__init__()
        self.client_cert, self.intermediate_cert = self.get_certificates_for_ip(ip_addr)


class ServerCertificateUtils(CertificateUtils):
    def __init__(self, ip_addr):
        super(ServerCertificateUtils, self).__init__()
        self.client_cert, self.intermediate_cert = self.get_certificates_for_ip(ip_addr)


if __name__ == '__main__':
    client = ClientCertificateUtils(None)
    server = ServerCertificateUtils(None)
    assert client.get_root_certificate() == server.get_root_certificate()
