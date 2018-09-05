import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import argparse
import os
import os.path

HOST_NAME = 'localhost'
PORT_NUMBER = 9000


class MyHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        if not os.path.isfile(self.path):
            self.send_response(400)
        else:
            self.send_error(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self.respond({'status': 200})

    def handle_http(self, status_code, path):
        self.send_response(status_code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        content = '''
        <html><head><title>Network Security</title></head>
        <body><p>File Requested</p>
        <p>You accessed path: {}</p>
        </body></html>
        '''.format(path)

        with open(self.path, 'rb') as file:
            content += """ {} """.format(file.read())

        return bytes(content, 'UTF-8')

    def respond(self, opts):
        response = self.handle_http(opts['status'], self.path)
        self.wfile.write(response)


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
    server_class = HTTPServer
    httpd = server_class((HOST_NAME, int(arguments.port)), MyHandler)
    print(time.asctime(), 'Server Starts - %s:%s' % (HOST_NAME, int(arguments.port)))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print(time.asctime(), 'Server Stops - %s:%s' % (HOST_NAME, int(arguments.port)))
