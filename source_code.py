import socket
import threading
import paramiko
import time


class SSHServer(paramiko.ServerInterface):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        with open('credentials.log', 'a') as f:
            f.write(f'Username: {username}, Password: {password}\n')
        if username == self.username and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        else:
            return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

class SSHChannel(paramiko.Channel):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.buffer = ''

    def send(self, data):
        self.buffer += data
        return len(data)

    def recv(self, nbytes):
        if self.buffer:
            data, self.buffer = self.buffer[:nbytes], self.buffer[nbytes:]
            return data
        return ''

    def send_exit_status(self, status):
        self.server.log(f'Exit Status: {status}\n')
        super().send_exit_status(status)

    def log(self, msg):
        self.server.log(msg)

def handle_connection(client, addr):
    transport = paramiko.Transport(client)
    transport.add_server_key(paramiko.RSAKey.generate(2048))
    server = SSHServer('adminn', 'password')
    server.channel = SSHChannel
    server.channel.server = server
    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        print('SSH negotiation failed.')
        return
    channel = transport.accept(1)
    if channel is None:
        print('SSH channel could not be established.')
        return
    print(f'Connection received from {addr[0]}:{addr[1]}')
    channel = SSHChannel(channel)
    while True:
        time.sleep(0.1)
        if not channel.active:
            break

def start_honeypot():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', 2222))
    s.listen(5)
    while True:
        try:
            client, addr = s.accept()
            t = threading.Thread(target=handle_connection, args=(client, addr))
            t.start()
        except Exception as e:
            print(f'Error: {e}')

start_honeypot()
