import socket
import threading
import struct
import sys
import os
import time
from datetime import datetime

server_socket = None

def handle_client(client_socket):
    client_ip, client_port = client_socket.getpeername()[:2]
    try:
        data = client_socket.recv(2)
        if not data or data[0] != 0x05:
            client_socket.close()
            return
        nmethods = data[1]
        methods = client_socket.recv(nmethods)

        client_socket.send(b"\x05\x00")

        data = client_socket.recv(4)
        if not data or data[0] != 0x05:
            client_socket.close()
            return
        cmd = data[1]
        atyp = data[3]

        if cmd != 1:
            client_socket.close()
            return

        if atyp == 1:
            addr = socket.inet_ntoa(client_socket.recv(4))
        elif atyp == 3:
            domain_len = ord(client_socket.recv(1))
            addr = client_socket.recv(domain_len).decode()
        elif atyp == 4:
            client_socket.close()
            return
        else:
            client_socket.close()
            return

        port = struct.unpack('>H', client_socket.recv(2))[0]

        try:
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((addr, port))
        except Exception:
            client_socket.send(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            client_socket.close()
            return

        bind_addr = remote_socket.getsockname()
        bind_ip = socket.inet_aton(bind_addr[0])
        bind_port = struct.pack('>H', bind_addr[1])
        reply = b"\x05\x00\x00\x01" + bind_ip + bind_port
        client_socket.send(reply)

        def forward(source, dest):
            try:
                while True:
                    data = source.recv(4096)
                    if not data:
                        break
                    dest.send(data)
            except:
                pass
            finally:
                source.close()
                dest.close()

        thread1 = threading.Thread(target=forward, args=(client_socket, remote_socket))
        thread2 = threading.Thread(target=forward, args=(remote_socket, client_socket))
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()

    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Ошибка при обработке клиента {client_ip}:{client_port}: {e}")
    finally:
        client_socket.close()

# Желательно менять только порт, айпи по необходимости
def run_server(host='0.0.0.0', port=1080):
    global server_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"SOCKS5 прокси (без авторизации) запущен на {host}:{port}")
    except Exception as e:
        print(f"Не удалось запустить сервер: {e}")
        sys.exit(1)

    while True:
        try:
            client_socket, addr = server_socket.accept()
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Новое подключение от {addr[0]}:{addr[1]}")
            thread = threading.Thread(target=handle_client, args=(client_socket,))
            thread.start()
        except (socket.error, OSError):
            break

if __name__ == "__main__":
    while True:
        server_thread = threading.Thread(target=run_server)
        server_thread.start()
        time.sleep(15 * 60)
        if server_socket:
            server_socket.close()
        server_thread.join()
        os.execv(sys.executable, [sys.executable] + sys.argv)