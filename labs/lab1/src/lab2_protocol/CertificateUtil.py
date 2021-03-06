import os
from logging import getLogger, DEBUG

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

logger = getLogger('playground.' + __name__)
logger.setLevel(DEBUG)


class CertificateUtils(object):

    def read_certificate_from_path(self, path):
        if os.path.exists(path):
            with open(path, 'rb') as file:
                return file.read()
        else:
            raise FileNotFoundError('File not found at {}'.format(path))

    def get_root_certificate(self):
        file = self.read_certificate_from_path(os.path.dirname(__file__) + '/certificates/20184_root_signed.cert')
        # file = self.read_certificate_from_path(os.path.dirname(__file__) + '/certificates/temp_root_cert.cert')
        return file

    def get_certificates_for_ip(self, ip_addr='5555.1.1.1'):
        # get these certs from file
        int_file = self.read_certificate_from_path(os.path.dirname(__file__) + '/certificates/temp_int_cert.cert')
        client_server_file = self.read_certificate_from_path(
            os.path.dirname(__file__) + '/certificates/tmp_client_cert.cert')
        return client_server_file, int_file

    def check_types(self, certs):
        for certificate in certs:
            if not isinstance(certificate, x509.Certificate):
                return False
        return True

    def validate_certificate_chain(self, certs):
        cert_obj = self.load_certs(certs)  # Convert certs to x509.Cert Objects
        if len(cert_obj) < 3 or not self.check_types(cert_obj):
            return False
        # if certs[2] != self.get_root_certificate():
        # return False
        # TODO: Match common name with IP?
        for idx in range(len(cert_obj) - 1):
            if cert_obj[idx].issuer != cert_obj[idx + 1].subject:
                logger.error(
                    "Issuer and subject do not match {} {}".format(cert_obj[idx].issuer, cert_obj[idx + 1].subject))
                return False
            try:
                # if not
                cert_obj[idx + 1].public_key().verify(cert_obj[idx].signature,
                                                      cert_obj[idx].tbs_certificate_bytes,
                                                      ec.ECDSA(hashes.SHA256()))  #:
                # logger.error("Signature does not match with public key")
                # return False
            except Exception as e:
                logger.error("Certificate verification failed with {}".format(e))
                return False
        return True

    def get_peer_public_key(self, certs):
        peer_cert = x509.load_pem_x509_certificate(certs[0], default_backend())
        return peer_cert.public_key()

    def load_certs(self, certs):
        temp = []
        for cert in certs:
            temp.append(x509.load_pem_x509_certificate(cert, default_backend()))
        return temp


class ClientCertificateUtils(CertificateUtils):
    def __init__(self, ip_addr='5555.1.1.1'):
        super(ClientCertificateUtils, self).__init__()
        # self.client_cert, self.intermediate_cert = self.get_certificates_for_ip(ip_addr)
        self.intermediate_cert = self.read_certificate_from_path(
            os.path.dirname(__file__) + '/certificates/' + ip_addr.split('.')[0] + '_signed.cert')
        self.client_cert = self.read_certificate_from_path(
            os.path.dirname(__file__) + '/certificates/' + ip_addr + '_signed.cert')


class ServerCertificateUtils(CertificateUtils):
    def __init__(self, ip_addr='5555.2.2.2'):
        super(ServerCertificateUtils, self).__init__()
        # self.server_cert, self.intermediate_cert = self.get_certificates_for_ip(ip_addr)
        self.intermediate_cert = self.read_certificate_from_path(
            os.path.dirname(__file__) + '/certificates/' + ip_addr.split('.')[0] + '_signed.cert')
        self.server_cert = self.read_certificate_from_path(
            os.path.dirname(__file__) + '/certificates/' + ip_addr + '_signed.cert')


if __name__ == '__main__':
    client = ClientCertificateUtils()
    server = ServerCertificateUtils()
    assert client.get_root_certificate() == server.get_root_certificate()
