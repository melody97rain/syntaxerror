#!/usr/bin/env python3
import socket, threading, select, sys, time, getopt, concurrent.futures

# Listen
LISTENING_ADDR = '127.0.0.1'
LISTENING_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 700

# Pass
PASS = ''

# Constants
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:69'
RESPONSE = 'HTTP/1.1 101 Script By Virtual\r\n\r\n'

MAX_WORKERS = 100

def log(msg):
    print(msg)

def handle_connection(client, server, addr):
    clientClosed = False
    targetClosed = True
    client_buffer = b''
    logmsg = f"Connection: {addr}"

    def close_all():
        nonlocal clientClosed, targetClosed
        try:
            if not clientClosed:
                client.shutdown(socket.SHUT_RDWR)
                client.close()
        except:
            pass
        clientClosed = True

        try:
            if not targetClosed:
                target.shutdown(socket.SHUT_RDWR)
                target.close()
        except:
            pass
        targetClosed = True

    try:
        client_buffer = client.recv(BUFLEN)
        headers = client_buffer.decode(errors='ignore')

        def findHeader(headers, key):
            for line in headers.split('\r\n'):
                if line.lower().startswith(key.lower() + ':'):
                    return line.split(':', 1)[1].strip()
            return ''

        hostPort = findHeader(headers, 'X-Real-Host') or DEFAULT_HOST
        if findHeader(headers, 'X-Split'):
            client.recv(BUFLEN)

        passwd = findHeader(headers, 'X-Pass')
        if PASS and passwd != PASS:
            client.sendall(b'HTTP/1.1 400 WrongPass!\r\n\r\n')
            return
        elif not PASS or hostPort.startswith(('127.0.0.1', 'localhost')):
            log(logmsg + f" - CONNECT {hostPort}")
            if ':' in hostPort:
                hostname, port = hostPort.split(':')
                port = int(port)
            else:
                hostname, port = hostPort, 443

            info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            af, socktype, proto, _, sa = info[0]
            target = socket.socket(af, socktype, proto)
            target.connect(sa)
            targetClosed = False

            client.sendall(RESPONSE.encode())
            socs = [client, target]
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
                            if sock is target:
                                client.sendall(data)
                            else:
                                target.sendall(data)
                            count = 0
                        except:
                            return
                count += 1
                if count >= TIMEOUT:
                    break
        else:
            client.sendall(b'HTTP/1.1 403 Forbidden!\r\n\r\n')
    except Exception as e:
        log(logmsg + f" - error: {e}")
    finally:
        close_all()
        with server.lock:
            server.active_connections.discard(threading.get_ident())

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = int(port)
        self.lock = threading.Lock()
        self.active_connections = set()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(2)
            s.bind((self.host, self.port))
            s.listen(100)
            log(f"Listening on {self.host}:{self.port}")

            while True:
                try:
                    c, addr = s.accept()
                    c.setblocking(True)
                    with self.lock:
                        if len(self.active_connections) >= MAX_WORKERS:
                            log(f"[!] Max connection limit reached. Rejecting {addr}")
                            c.close()
                            continue
                        ident = threading.get_ident()
                        self.active_connections.add(ident)
                    self.executor.submit(handle_connection, c, self, addr)
                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    log("[!] Server stopping...")
                    break
                except Exception as e:
                    log(f"[!] Accept error: {e}")


def main():
    print("\n:-------PythonProxy-------:")
    print(f"Listening addr: {LISTENING_ADDR}")
    print(f"Listening port: {LISTENING_PORT}\n")
    print(":-------------------------:\n")
    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()

if __name__ == '__main__':
    main()
