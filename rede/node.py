import socket
import random
from zkp import SchnorrZKP

class VehicleNode:
    def __init__(self, ip, port, bootstrap_ip, bootstrap_port, p, q, g):
        self.ip = ip
        self.port = port
        self.bootstrap_ip = bootstrap_ip
        self.bootstrap_port = bootstrap_port
        self.peers = []
        self.zkp = SchnorrZKP(p, q, g)
        self.peer_public_keys = {}

    def register_with_bootstrap(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.bootstrap_ip, self.bootstrap_port))
            msg = f"REGISTER {self.ip} {self.port} {self.zkp.public}"
            s.send(msg.encode())
            peer_list = s.recv(4096).decode()

            self.peers = []
            for entry in peer_list.split(";"):
                if entry:
                    parts = entry.split(":")
                    if len(parts) == 3:
                        ip, port, public_key = parts
                        self.peers.append((ip, port))
                        self.peer_public_keys[(ip, port)] = int(public_key)
            print(f"[Node {self.port}] Peers: {self.peers}")

    def listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.ip, self.port))
        server.listen()

        while True:
            conn, addr = server.accept()
            data = conn.recv(4096).decode()
            parts = data.split('|')

            if parts[0] == 'AUTH':
                R = int(parts[1])
                challenge = random.randint(1, 2**128)
                conn.send(str(challenge).encode())

                s_recv = int(conn.recv(4096).decode())

                peer_public = self.peer_public_keys.get((addr[0], str(addr[1])), None)
                if peer_public is None:
                    peer_public = self.extract_public_from_message(parts)

                if peer_public is None:
                    print(f"[Node {self.port}] No public key found for peer {addr}")
                    conn.send("FAIL".encode())
                    conn.close()
                    continue
                
                verified = self.zkp.verify(R, peer_public, challenge, s_recv)
                if verified:
                    conn.send("OK".encode())
                    message = conn.recv(4096).decode()
                    print(f"[Node {self.port}] Authenticated message: {message}")
                else:
                    conn.send("FAIL".encode())

            conn.close()

    def extract_public_from_message(self, parts):
        # fallback if address lookup fails
        for ip, port in self.peers:
            if port == parts[-2]:
                return self.peer_public_keys.get((ip, port))
        return None

    def send_authenticated_message(self, peer_ip, peer_port, message):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((peer_ip, int(peer_port)))
                R = self.zkp.create_commitment()
                s.send(f"AUTH|{R}|{self.port}".encode())

                challenge = int(s.recv(4096).decode())
                s_value = self.zkp.compute_response(challenge)
                s.send(str(s_value).encode())

                result = s.recv(4096).decode()
                if result == "OK":
                    s.send(message.encode())
                    print(f"[Node {self.port}] Authenticated and sent message")
                else:
                    print(f"[Node {self.port}] Authentication failed")
        except Exception as e:
            print(f"[Node {self.port}] Connection failed: {e}")
