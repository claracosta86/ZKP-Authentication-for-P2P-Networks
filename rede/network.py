import socket
import threading

class BootstrapServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = []  # (ip, port, public_key)

    def start(self):
        print(f"[Bootstrap] Starting server at {self.host}:{self.port}")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen()

        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        data = conn.recv(4096).decode()
        if data.startswith("REGISTER"):
            _, peer_ip, peer_port, public_key = data.split()
            self.peers.append((peer_ip, peer_port, public_key))
            print(f"[Bootstrap] Registered peer: {peer_ip}:{peer_port}")

            peer_list = ";".join([f"{ip}:{port}:{pub}" for ip, port, pub in self.peers])
            conn.send(peer_list.encode())

        conn.close()
