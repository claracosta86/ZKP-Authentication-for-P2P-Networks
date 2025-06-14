import hashlib
import secrets
import socket
import random

from rede.models.ca_models import RegisterCertificateRequest, Certificate
from zkp import SchnorrZKP

class VehicleNode:
    def __init__(self, ip, port, bootstrap_ip, bootstrap_port, ca_public_key, p, q, g):
        """
        Initializes a VehicleNode instance.

        Args:
            ip (str): The IP address of the node.
            port (int): The port number of the node.
            bootstrap_ip (str): The IP address of the bootstrap node.
            bootstrap_port (int): The port number of the bootstrap node.
            p (int): A prime number used in the Zero-Knowledge Proof (ZKP) protocol.
            q (int): A prime divisor of (p-1) used in the ZKP protocol.
            g (int): A generator for the cyclic group used in the ZKP protocol.

        Attributes:
            ip (str): Stores the IP address of the node.
            port (int): Stores the port number of the node.
            certificate (str): Stores the certificate of the node.
            bootstrap_ip (str): Stores the IP address of the bootstrap node.
            bootstrap_port (int): Stores the port number of the bootstrap node.
            peers (list): A list of tuples containing the IP and port of connected peers.
            zkp (SchnorrZKP): An instance of the Schnorr Zero-Knowledge Proof protocol.
        """

        self.id = f"Vehicle{port}"
        self.ip = ip
        self.port = port
        self.certificate = None
        self.bootstrap_ip = bootstrap_ip
        self.bootstrap_port = bootstrap_port
        self.peers = []
        self.ca_public_key = ca_public_key

        self.p = p
        self.q = q
        self.g = g
        self.private_key = self.init_private_key() # private key
        self.public_key = pow(self.g, self.private_key, self.p) # public key

        self.zkp = SchnorrZKP(p, q, g)
        self.peer_public_keys = {}

    def set_certificate(self, certificate):
        self.certificate = certificate

    def init_private_key(self):
        # Generate a random number ru
        ru = secrets.randbelow(self.q)
        h = hashlib.sha256()
        # Hash the id and ru
        h.update(self.id.encode('utf-8'))
        h.update(str(ru).encode('utf-8'))

        return int.from_bytes(h.digest(), 'big') % self.q

    def get_registration_request(self):
        return RegisterCertificateRequest(self.id, self.public_key)

    def validate_certificate(self, certificate: Certificate) -> bool:
        """
        Validates a certificate using Schnorr signature verification.

        Args:
            certificate (Certificate): Certificate containing (public_key, r, s)

        Returns:
            bool: True if signature is valid
        """
        # Convert integers to fixed-width bytes
        pub_key_bytes = certificate.public_key.to_bytes(256, byteorder='big')
        r_bytes = certificate.r.to_bytes(256, byteorder='big')

        # Concatenate bytes directly
        e = int.from_bytes(hashlib.sha256(pub_key_bytes + r_bytes).digest(), 'big') % self.q

        left = pow(self.g, certificate.s, self.p)
        right = (certificate.r * pow(self.ca_public_key, e, self.p)) % self.p

        return left == right

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
