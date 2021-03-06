from socket import *
import argparse

HOST = ''
PORT = 12328


def connect(host, port):
    server_sock = socket(AF_INET, SOCK_STREAM)

    server_sock.bind((host, port))

    server_sock.listen(5)

    conn, addr = server_sock.accept()

    print('Connected by', addr)

    while True:
        data = conn.recv(1024)
        if not data:
            break
        conn.sendall(data)

    conn.close()


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
