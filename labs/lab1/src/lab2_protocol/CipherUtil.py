from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
import hashlib


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


class ClientCipherUtils(CipherUtils):
    def __init__(self):
        super(ClientCipherUtils, self).__init__()
        self.private_key, self.public_key = self.generate_private_public_keypair()
        self.shared_key = None

    def generate_client_shared(self, peer_pub_key):
        self.shared_key = self.generate_shared_key(priv_key=self.private_key, peer_pub_key=peer_pub_key)
        return self.shared_key

    def generate_client_keys(self, client_hello, server_hello):
        client_iv, _, client_read, client_write = self.key_derivation(self.shared_key,
                                                                      client_hello + server_hello)
        return client_iv, client_read, client_write


class ServerCipherUtils(CipherUtils):
    def __init__(self):
        super(ServerCipherUtils, self).__init__()
        self.private_key, self.public_key = self.generate_private_public_keypair()
        self.shared_key = None

    def generate_server_shared(self, peer_pub_key):
        self.shared_key = self.generate_shared_key(priv_key=self.private_key, peer_pub_key=peer_pub_key)
        return self.shared_key

    def generate_server_keys(self, client_hello, server_hello):
        _, server_iv, server_write, server_read = self.key_derivation(self.shared_key,
                                                                      client_hello + server_hello)
        return server_iv, server_write, server_read


if __name__ == '__main__':
    client = ClientCipherUtils()
    server = ServerCipherUtils()
    assert client.generate_client_shared(server.public_key) == server.generate_server_shared(client.public_key)
    assert client.generate_client_keys(b'a', b'b')[1] == server.generate_server_keys(b'a', b'b')[1]
    assert client.generate_client_keys(b'a', b'b')[2] == server.generate_server_keys(b'a', b'b')[2]
