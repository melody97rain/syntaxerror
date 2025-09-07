#!/usr/bin/env python3
import socket, threading, select, signal, sys, time, getopt

LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 789

PASS = ''

BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:109'
RESPONSE = (
    'HTTP/1.1 101 <b><u><font color="blue">(HTTP)Server By NiLphreakz</font></b>\r\n\r\n'
    'Content-Length: 104857600000\r\n\r\n'
)

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = int(port)
        self.running = False
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def printLog(self, log):
        with self.logLock:
            print(log)

    def serve_forever(self):
        self.running = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(100)
            s.settimeout(2)
            self.printLog(f"Listening on {self.host}:{self.port}")

            while self.running:
                try:
                    c, addr = s.accept()
                    c.setblocking(1)
                    handler = ConnectionHandler(c, self, addr)
                    handler.daemon = True
                    handler.start()
                    with self.threadsLock:
                        self.threads.append(handler)
                except socket.timeout:
                    continue
                except Exception as e:
                    self.printLog(f"Accept error: {e}")

    def stop(self):
        self.running = False
        with self.threadsLock:
            for t in self.threads:
                if t.is_alive():
                    t.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, client_sock, server, addr):
        super().__init__()
        self.client = client_sock
        self.server = server
        self.addr = addr
        self.clientClosed = False
        self.targetClosed = True
        self.client_buffer = b''
        self.log = f"Connection: {addr}"

    def close(self):
        if not self.clientClosed:
            try:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
            except:
                pass
            self.clientClosed = True

        if not self.targetClosed:
            try:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
            except:
                pass
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
            headers = self.client_buffer.decode(errors='ignore')

            hostPort = self.findHeader(headers, 'X-Real-Host') or DEFAULT_HOST
            if self.findHeader(headers, 'X-Split'):
                self.client.recv(BUFLEN)

            if hostPort:
                passwd = self.findHeader(headers, 'X-Pass')
                if PASS and passwd != PASS:
                    self.client.sendall(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif PASS == '' or hostPort.startswith(('127.0.0.1', 'localhost')):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.sendall(b'HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                self.server.printLog('- No X-Real-Host!')
                self.client.sendall(b'HTTP/1.1 400 NoXRealHost!\r\n\r\n')
        except Exception as e:
            self.server.printLog(self.log + f' - error: {str(e)}')
        finally:
            self.close()

    def findHeader(self, data, header):
        for line in data.split('\r\n'):
            if line.lower().startswith(header.lower() + ':'):
                return line.split(':', 1)[1].strip()
        return ''

    def connect_target(self, host):
        host, port = (host.split(':') + [443])[:2]
        port = int(port)
        info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        af, socktype, proto, _, sa = info[0]
        self.target = socket.socket(af, socktype, proto)
        self.target.connect(sa)
        self.targetClosed = False

    def method_CONNECT(self, path):
        self.log += f' - CONNECT {path}'
        self.connect_target(path)
        self.client.sendall(RESPONSE.encode())
        self.client_buffer = b''
        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        sockets = [self.client, self.target]
        count = 0
        while True:
            readable, _, error = select.select(sockets, [], sockets, 3)
            if error:
                break
            if readable:
                for sock in readable:
                    try:
                        data = sock.recv(BUFLEN)
                        if data:
                            if sock is self.target:
                                self.client.sendall(data)
                            else:
                                self.target.sendall(data)
                            count = 0
                        else:
                            return
                    except:
                        return
            count += 1
            if count >= TIMEOUT:
                break

def print_usage():
    print('Usage: proxy.py -p <port>')
    print('       proxy.py -b <bindAddr> -p <port>')
    print('       proxy.py -b 0.0.0.0 -p 80')

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT
    try:
        opts, args = getopt.getopt(argv, "hb:p:", ["bind=", "port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ('-b', '--bind'):
            LISTENING_ADDR = arg
        elif opt in ('-p', '--port'):
            LISTENING_PORT = int(arg)

def main():
    parse_args(sys.argv[1:])
    print("\n:-------PythonProxy-------:")
    print(f"Listening addr: {LISTENING_ADDR}")
    print(f"Listening port: {LISTENING_PORT}\n")
    print(":-------------------------:\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('Stopping...')
        server.stop()

if __name__ == '__main__':
    main()

