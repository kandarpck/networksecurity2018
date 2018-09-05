import requests
import argparse

HOST_NAME = 'http://127.0.0.1'
PORT_NUMBER = "9000"


def get_file(path, port):
    file = requests.get(HOST_NAME + ":" + port + "/" + path)
    print(file.text)


def get_args():
    parser = argparse.ArgumentParser(description='Simple HTTP Server')
    parser.add_argument('file', help='File path', nargs='?')
    parser.add_argument('port', default=PORT_NUMBER,
                        help='Port',
                        nargs='?')

    args = parser.parse_args()

    return args


if __name__ == '__main__':
    arguments = get_args()
    get_file(arguments.file, arguments.port)
