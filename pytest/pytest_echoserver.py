from socket import *

HOST = ''
PORT = 12328

server_sock = socket(AF_INET, SOCK_STREAM)

server_sock.bind((HOST, PORT))

server_sock.listen(5)

conn, addr = server_sock.accept()

print('Connected by', addr)

while True:
    data = conn.recv(1024)
    if not data:
        break
    conn.sendall(data)

conn.close()
