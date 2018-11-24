from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class CipherUtils(object):

    def generate_private_public_keypair(self):
        private_key = X25519PrivateKey.generate()
        return private_key, private_key.public_key()

    def generate_shared_key(self, priv_key, peer_pub_key):
        return priv_key.exchange(peer_pub_key)


class ClientCipherUtils(CipherUtils):
    def __init__(self):
        super(ClientCipherUtils, self).__init__()
        self.private_key, self.public_key = self.generate_private_public_keypair()
        self.shared_key = None

    def generate_client_shared(self, peer_pub_key):
        self.shared_key = self.generate_shared_key(priv_key=self.private_key, peer_pub_key=peer_pub_key)
        return self.shared_key


class ServerCipherUtils(CipherUtils):
    def __init__(self):
        super(ServerCipherUtils, self).__init__()
        self.private_key, self.public_key = self.generate_private_public_keypair()
        self.shared_key = None

    def generate_server_shared(self, peer_pub_key):
        self.shared_key = self.generate_shared_key(priv_key=self.private_key, peer_pub_key=peer_pub_key)
        return self.shared_key


if __name__ == '__main__':
    client = ClientCipherUtils()
    server = ServerCipherUtils()
    assert client.generate_client_shared(server.public_key) == server.generate_server_shared(client.public_key)
