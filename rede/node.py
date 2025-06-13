import socket

class VehicleNode:
    def __init__(self, ip, port, bootstrap_ip, bootstrap_port):
        self.ip = ip
        self.port = port
        self.bootstrap_ip = bootstrap_ip
        self.bootstrap_port = bootstrap_port
        self.peers = []

    def register_with_bootstrap(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.bootstrap_ip, self.bootstrap_port))
            msg = f"REGISTER {self.ip} {self.port}"
            s.send(msg.encode())
            peer_list = s.recv(4096).decode()

            self.peers = [tuple(p.split(":")) for p in peer_list.split(";") if p]
            print(f"[Node {self.port}] Peers: {self.peers}")

    def listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((self.ip, self.port))
        server.listen()

        while True:
            conn, addr = server.accept()
            data = conn.recv(1024).decode()
            print(f"[Node {self.port}] Received message: {data}")
            conn.close()

    def send_message(self, message):
        for peer_ip, peer_port in self.peers:
            if int(peer_port) != self.port:  # Don't send to itself
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((peer_ip, int(peer_port)))
                        s.send(message.encode())
                except Exception as e:
                    print(f"[Node {self.port}] Failed to send to {peer_ip}:{peer_port}: {e}")
