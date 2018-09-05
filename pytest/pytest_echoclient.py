from socket import *

HOST = '127.0.0.1'
PORT = 12328

sock = socket(AF_INET, SOCK_STREAM)

sock.connect((HOST, PORT))

sock.sendall(b'Hello World!')
data = sock.recv(1024)

print('Received', repr(data.decode()))

sock.close()
