import hashlib
import os
from logging import getLogger, DEBUG

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = getLogger('playground.' + __name__)
logger.setLevel(DEBUG)


class CipherUtils(object):

    def generate_private_public_keypair(self):
        private_key = x25519.X25519PrivateKey.generate()
        return private_key, private_key.public_key()

    def generate_shared_key(self, priv_key, peer_pub_key):
        loaded_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_key)
        return priv_key.exchange(loaded_key)

    def key_derivation(self, secret, hellos):
        hasher = hashlib.sha256()
        hasher.update(secret + hellos)
        block_1 = hasher.digest()
        hasher.update(block_1)
        block_2 = hasher.digest()
        iv_1 = block_1[:12]
        iv_2 = block_1[12:24]
        key_1 = block_2[:16]
        key_2 = block_2[16:]
        return iv_1, iv_2, key_1, key_2

    def get_ecdsa_key(self, path):
        with open(path, 'rb') as f:
            loaded_key = f.read()

        return serialization.load_pem_private_key(loaded_key, password=None, backend=default_backend())


class ClientCipherUtils(CipherUtils):
    def __init__(self):
        super(ClientCipherUtils, self).__init__()
        self.private_key, self.public_key = self.generate_private_public_keypair()
        self.shared_key = None
        self.ecdsa_key = self.get_ecdsa_key(os.path.dirname(__file__) + '/certificates/tempclient_prkey.pem')
        self.client_iv, self.server_iv, self.client_read, self.client_write = None, None, None, None
        self.hello_messages = None

    def generate_client_shared(self, peer_pub_key):
        self.shared_key = self.generate_shared_key(priv_key=self.private_key, peer_pub_key=peer_pub_key)
        return self.shared_key

    def generate_client_keys(self, client_hello, server_hello):
        self.client_iv, self.server_iv, self.client_read, self.client_write = self.key_derivation(self.shared_key,
                                                                                                  client_hello +
                                                                                                  server_hello)
        return self.client_iv, self.server_iv, self.client_read, self.client_write

    def get_signature(self, client_hello, server_hello):
        # Get Signature for Finish packets
        # Hash hello messages
        hasher = hashes.Hash(hashes.SHA256(), default_backend())
        hasher.update(client_hello + server_hello)
        self.hello_messages = hasher.finalize()
        # Sign using ECDSA key
        signature = self.ecdsa_key.sign(self.hello_messages, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify_signature(self, peer_key, sig):
        # Verify signature of received peer Finish packet
        try:
            peer_key.verify(sig, self.hello_messages, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception as e:
            logger.error("Finish signature verification failed with {}".format(e))
            return False
        return True

    def encrypt_data(self, ct):
        aesgcm = AESGCM(self.client_write)
        return aesgcm.encrypt(self.client_iv, ct, None)

    def server_decrypt(self, ct):
        aesgcm = AESGCM(self.client_read)
        return aesgcm.decrypt(self.server_iv, ct, None)


class ServerCipherUtils(CipherUtils):
    def __init__(self):
        super(ServerCipherUtils, self).__init__()
        self.private_key, self.public_key = self.generate_private_public_keypair()
        self.shared_key = None
        self.ecdsa_key = self.get_ecdsa_key(os.path.dirname(__file__) + '/certificates/tempserver_prkey.pem')
        self.client_iv, self.server_iv, self.server_read, self.server_write = None, None, None, None
        self.hello_messages = None

    def generate_server_shared(self, peer_pub_key):
        self.shared_key = self.generate_shared_key(priv_key=self.private_key, peer_pub_key=peer_pub_key)
        return self.shared_key

    def generate_server_keys(self, client_hello, server_hello):
        self.client_iv, self.server_iv, self.server_write, self.server_read = self.key_derivation(self.shared_key,
                                                                                                  client_hello +
                                                                                                  server_hello)
        return self.client_iv, self.server_iv, self.server_write, self.server_read

    def get_signature(self, client_hello, server_hello):
        # Signature for FINISH Packets
        # Hash hello messages
        hasher = hashes.Hash(hashes.SHA256(), default_backend())
        hasher.update(client_hello + server_hello)
        self.hello_messages = hasher.finalize()
        # Sign using ECDSA key
        signature = self.ecdsa_key.sign(self.hello_messages, ec.ECDSA(hashes.SHA256()))
        return signature

    def verify_signature(self, peer_key, sig):
        # Verify signature from received peer Finish packet
        try:
            peer_key.verify(sig, self.hello_messages, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception as e:
            logger.error("Finish signature verification failed with {}".format(e))
            return False
        return True

    def encrypt_data(self, ct):
        aesgcm = AESGCM(self.server_write)
        return aesgcm.encrypt(self.server_iv, ct, None)

    def client_decrypt(self, ct):
        aesgcm = AESGCM(self.server_read)
        return aesgcm.decrypt(self.client_iv, ct, None)


if __name__ == '__main__':
    client = ClientCipherUtils()
    server = ServerCipherUtils()
    assert client.generate_client_shared(server.public_key) == server.generate_server_shared(client.public_key)
    assert client.generate_client_keys(b'a', b'b')[2] == server.generate_server_keys(b'a', b'b')[2]
    assert client.generate_client_keys(b'a', b'b')[3] == server.generate_server_keys(b'a', b'b')[3]
