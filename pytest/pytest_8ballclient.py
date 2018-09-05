from socket import *
import argparse

HOST = '127.0.0.1'
PORT = 12328


def connect(host, port):
    sock = socket(AF_INET, SOCK_STREAM)

    sock.connect((host, port))

    sock.sendall(b'Hello World!')
    data = sock.recv(1024)

    print('Received', repr(data.decode()))

    sock.close()


def get_args():
    parser = argparse.ArgumentParser(description='Echo')
    parser.add_argument('host', default=HOST, help='', nargs='?')
    parser.add_argument('port', default=PORT,
                        help='Port',
                        nargs='?')

    args = parser.parse_args()

    return args


if __name__ == '__main__':
    arguments = get_args()
    connect(arguments.host, arguments.port)
