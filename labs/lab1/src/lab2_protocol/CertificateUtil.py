import os
from logging import getLogger, DEBUG

from cryptography import x509
from cryptography.hazmat.primitives.hashes import SHA256

logger = getLogger('playground.' + __name__)
logger.setLevel(DEBUG)


class CertificateUtils(object):

    def read_certificate_from_path(self, path):
        if os.path.exists(path):
            with open(path, 'r+b') as file:
                return file.read()
        else:
            raise FileNotFoundError('File not found at {}'.format(path))

    def get_root_certificate(self):
        return self.read_certificate_from_path(os.path.dirname(__file__) + '/certificates/20184_root_signed.cert')

    def get_certificates_for_ip(self, ip_addr):
        return None, None

    def check_types(self, certs):
        for certificate in certs:
            if not isinstance(certificate, x509.Certificate):
                return False
        return True

    def validate_certificate_chain(self, certs):
        if len(certs) < 3 or not self.check_types(certs):
            return False
        if certs[2] != self.get_root_certificate():
            return False
        # TODO: Match common name with IP?
        for idx in range(len(certs) - 1):
            if certs[idx].issuer != certs[idx + 1].subject:
                logger.error("Issuer and subject do not match {} {}".format(certs[idx].issuer, certs[idx + 1].subject))
                return False
            try:
                if not certs[idx + 1].public_key().verify(certs[idx].signature,
                                                          certs[idx].tbs_certificate_bytes,
                                                          SHA256()):
                    logger.error("Signature does not match with public key")
                    return False
            except Exception as e:
                logger.error("Certificate verification failed with {}".format(e))
                return False
        return True


class ClientCertificateUtils(CertificateUtils):
    def __init__(self, ip_addr):
        super(ClientCertificateUtils, self).__init__()
        self.client_cert, self.intermediate_cert = self.get_certificates_for_ip(ip_addr)


class ServerCertificateUtils(CertificateUtils):
    def __init__(self, ip_addr):
        super(ServerCertificateUtils, self).__init__()
        self.server_cert, self.intermediate_cert = self.get_certificates_for_ip(ip_addr)


if __name__ == '__main__':
    client = ClientCertificateUtils(None)
    server = ServerCertificateUtils(None)
    assert client.get_root_certificate() == server.get_root_certificate()
