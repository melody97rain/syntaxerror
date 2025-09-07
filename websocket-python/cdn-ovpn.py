#!/usr/bin/env python3
import socket, threading, select, sys, time, getopt

# Listen config
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 753
PASS = ''

# Constants
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:1194'
RESPONSE = (
    'HTTP/1.1 101 <b><u><font color="blue">Script By Virtual t.me/Virtual_NW</font></b>\r\n\r\n'
    'Content-Length: 104857600000\r\n\r\n'
)

MAX_THREADS = 100  # Limit maximum concurrent threads

class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.running = False
        self.host = host
        self.port = int(port)
        self.threads = []
        self.lock = threading.Lock()

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(2)
            s.bind((self.host, self.port))
            s.listen(5)
            self.running = True

            while self.running:
                try:
                    c, addr = s.accept()
                    c.setblocking(True)
                    with self.lock:
                        if len(self.threads) >= MAX_THREADS:
                            print(f"[!] Max threads reached: {MAX_THREADS}. Connection from {addr} refused.")
                            c.close()
                            continue
                        conn = ConnectionHandler(c, self, addr)
                        conn.daemon = True
                        conn.start()
                        self.threads.append(conn)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[!] Accept Error: {e}")

    def log(self, msg):
        print(msg)

    def removeConn(self, conn):
        with self.lock:
            if conn in self.threads:
                self.threads.remove(conn)

    def close(self):
        self.running = False
        with self.lock:
            for t in self.threads:
                t.close()

class ConnectionHandler(threading.Thread):
    def __init__(self, client, server, addr):
        super().__init__()
        self.client = client
        self.server = server
        self.addr = addr
        self.clientClosed = False
        self.targetClosed = True
        self.client_buffer = b''
        self.logmsg = f"Connection: {addr}"

    def close(self):
        if not self.clientClosed:
            try:
                self.client.shutdown(socket.SHUT_RDWR)
            except:
                pass
            self.client.close()
            self.clientClosed = True

        if not self.targetClosed:
            try:
                self.target.shutdown(socket.SHUT_RDWR)
            except:
                pass
            self.target.close()
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)
            headers = self.client_buffer.decode(errors='ignore')

            hostPort = self.findHeader(headers, 'X-Real-Host') or DEFAULT_HOST
            if self.findHeader(headers, 'X-Split'):
                self.client.recv(BUFLEN)

            passwd = self.findHeader(headers, 'X-Pass')
            if PASS and passwd != PASS:
                self.client.sendall(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
            elif PASS == '' or hostPort.startswith(('127.0.0.1', 'localhost')):
                self.method_CONNECT(hostPort)
            else:
                self.client.sendall(b'HTTP/1.1 403 Forbidden!\r\n\r\n')
        except Exception as e:
            self.server.log(self.logmsg + f" - error: {e}")
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, headers, key):
        for line in headers.split('\r\n'):
            if line.lower().startswith(key.lower() + ':'):
                return line.split(':', 1)[1].strip()
        return ''

    def connect_target(self, host):
        if ':' in host:
            hostname, port = host.split(':')
            port = int(port)
        else:
            hostname, port = host, 443

        info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        af, socktype, proto, _, sa = info[0]
        self.target = socket.socket(af, socktype, proto)
        self.target.connect(sa)
        self.targetClosed = False

    def method_CONNECT(self, path):
        self.server.log(self.logmsg + f" - CONNECT {path}")
        self.connect_target(path)
        self.client.sendall(RESPONSE.encode())
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0

        while True:
            r, _, e = select.select(socs, [], socs, 3)
            if e:
                break
            if r:
                for sock in r:
                    try:
                        data = sock.recv(BUFLEN)
                        if not data:
                            return
                        if sock is self.target:
                            self.client.sendall(data)
                        else:
                            self.target.sendall(data)
                        count = 0
                    except:
                        return
            count += 1
            if count >= TIMEOUT:
                break

def print_usage():
    print("Usage: proxy.py -p <port>")
    print("       proxy.py -b <bindAddr> -p <port>")

def parse_args(argv):
    global LISTENING_ADDR, LISTENING_PORT
    try:
        opts, _ = getopt.getopt(argv, "hb:p:", ["bind=", "port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)

def main():
    parse_args(sys.argv[1:])
    print("\n:-------PythonProxy-------:")
    print(f"Listening addr: {LISTENING_ADDR}")
    print(f"Listening port: {LISTENING_PORT}\n")
    print(":-------------------------:\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print("Stopping...")
        server.close()

if __name__ == '__main__':
    main()
