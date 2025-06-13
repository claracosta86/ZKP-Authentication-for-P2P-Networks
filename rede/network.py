import socket
import threading

class BootstrapServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = []  # (ip, port)

    def start(self):
        print(f"[Bootstrap] Starting server at {self.host}:{self.port}")
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.host, self.port))
        server.listen()

        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        data = conn.recv(1024).decode()
        if data.startswith("REGISTER"):
            _, peer_ip, peer_port = data.split()
            self.peers.append((peer_ip, peer_port))
            print(f"[Bootstrap] Registered peer: {peer_ip}:{peer_port}")

            # Return full peer list
            peer_list = ";".join([f"{ip}:{port}" for ip, port in self.peers])
            conn.send(peer_list.encode())

        conn.close()
