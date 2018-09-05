from socket import *
import argparse
import random

HOST = ''
PORT = 12328

responses = ['Your guess is as good as mine.',
             'You need a vacation.',
             'Its Trumps fault!',
             'I dont know. What do you think?',
             'Nobody ever said it would be easy, they only said it would be worth it.',
             'You really expect me to answer that?',
             'Youre going to get what you deserve.',
             'That depends on how much youre willing to pay.']

data_response_mapping = dict()


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
        if not data_response_mapping.get(data):
            data_response_mapping[data] = random.choice(responses)
        conn.sendall(data_response_mapping[data])

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
