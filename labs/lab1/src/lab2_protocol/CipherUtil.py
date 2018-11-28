import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# TODO: Add client, server_encrypt for transport.write?

class CipherUtils(object):

    def generate_private_public_keypair(self):
        private_key = X25519PrivateKey.generate()
        return private_key, private_key.public_key()

    def generate_shared_key(self, priv_key, peer_pub_key):
        return priv_key.exchange(peer_pub_key)

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

    def generate_signature(self, secret, hellos):
        sign = hashlib.sha256()
        sign.update(secret + hellos)
        return sign.digest()


class ClientCipherUtils(CipherUtils):
    def __init__(self):
        super(ClientCipherUtils, self).__init__()
        self.private_key, self.public_key = self.generate_private_public_keypair()
        self.shared_key = None
        self.client_iv, self.server_iv, self.client_read, self.client_write = None, None, None, None

    def generate_client_shared(self, peer_pub_key):
        self.shared_key = self.generate_shared_key(priv_key=self.private_key, peer_pub_key=peer_pub_key)
        return self.shared_key

    def generate_client_keys(self, client_hello, server_hello):
        self.client_iv, self.server_iv, self.client_read, self.client_write = self.key_derivation(self.shared_key,
                                                                                                  client_hello +
                                                                                                  server_hello)
        return self.client_iv, self.server_iv, self.client_read, self.client_write

    def get_signature(self, client_hello, server_hello):
        signature = self.generate_signature(self.private_key, client_hello + server_hello)
        return signature

    def server_decrypt(self, ct):
        aesgcm = AESGCM(self.client_read)
        return aesgcm.decrypt(self.server_iv, ct, None)


class ServerCipherUtils(CipherUtils):
    def __init__(self):
        super(ServerCipherUtils, self).__init__()
        self.private_key, self.public_key = self.generate_private_public_keypair()
        self.shared_key = None
        self.client_iv, self.server_iv, self.server_read, self.server_write = None, None, None, None

    def generate_server_shared(self, peer_pub_key):
        self.shared_key = self.generate_shared_key(priv_key=self.private_key, peer_pub_key=peer_pub_key)
        return self.shared_key

    def generate_server_keys(self, client_hello, server_hello):
        self.client_iv, self.server_iv, self.server_write, self.server_read = self.key_derivation(self.shared_key,
                                                                                                  client_hello +
                                                                                                  server_hello)
        return self.client_iv, self.server_iv, self.server_write, self.server_read

    def get_signature(self, client_hello, server_hello):
        signature = self.generate_signature(self.private_key, client_hello + server_hello)
        return signature

    def client_decrypt(self, ct):
        aesgcm = AESGCM(self.server_read)
        return aesgcm.decrypt(self.client_iv, ct, None)


if __name__ == '__main__':
    client = ClientCipherUtils()
    server = ServerCipherUtils()
    assert client.generate_client_shared(server.public_key) == server.generate_server_shared(client.public_key)
    assert client.generate_client_keys(b'a', b'b')[2] == server.generate_server_keys(b'a', b'b')[2]
    assert client.generate_client_keys(b'a', b'b')[3] == server.generate_server_keys(b'a', b'b')[3]
