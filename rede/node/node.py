import hashlib
import pickle
import secrets
import socket
import random
import time
from typing import Set, List

from rede.models.authentication import AuthenticationRequest, AuthenticationCommitmentRequest, \
    AuthenticationVerificationRequest
from rede.models.ca_models import RegisterCertificateRequest, Certificate
from rede.utils import validate
from rede.utils.validate import validate_key_pair
from rede.zkp import SchnorrZKP

class Node:
    def __init__(self, ip, port, bootstrap_host, bootstrap_port, p, q, g, monitor=None, ca_public_key=None):
        """
        Initializes a Node instance.

        Args:
            ip (str): The IP address of the node.
            port (int): The port number of the node.
            bootstrap_host (str): The IP address of the bootstrap node.
            bootstrap_port (int): The port number of the bootstrap node.
            p (int): A prime number used in the Zero-Knowledge Proof (ZKP) protocol.
            q (int): A prime divisor of (p-1) used in the ZKP protocol.
            g (int): A generator for the cyclic group used in the ZKP protocol.
            monitor (Monitor, optional): An instance of the Monitor class for tracking metrics. Defaults to None.
            ca_public_key (int, optional): The public key of the Certificate Authority (CA) for certificate validation. Defaults to None.

        Attributes:
            ip (str): Stores the IP address of the node.
            port (int): Stores the port number of the node.
            certificate (str): Stores the certificate of the node.
            bootstrap_host (str): Stores the IP address of the bootstrap node.
            bootstrap_port (int): Stores the port number of the bootstrap node.
            peers (list): A list of tuples containing the IP and port of connected peers.
            zkp (SchnorrZKP): An instance of the Schnorr Zero-Knowledge Proof protocol.
        """

        self.id = f"Node{port}"
        self.ip = ip
        self.port = port
        self.bootstrap_host = bootstrap_host
        self.bootstrap_port = bootstrap_port
        self.certificate = None
        self.certificates = set()
        self.certificates_n = 5
        self.peer_challenges = {}
        self.peer_U = {}
        self.peers_allowed = []
        self.peers_authenticated_at = []


        self.p = p
        self.q = q
        self.g = g
        self.private_key = self.init_private_key() # private key
        self.public_key = pow(self.g, self.private_key, self.p)

        self.zkp = SchnorrZKP(p, q, g, self.private_key)

        self.ca_public_key = ca_public_key  # Public key of the CA for certificate validation
        self.monitor = monitor

    def set_certificate(self, certificate: Certificate):
        self.certificate = certificate

    def set_certificates(self, certificates: set[Certificate]):
        self.certificates = certificates

    def init_private_key(self):
        # Generate a random number ru
        ru = secrets.randbelow(self.q)
        h = hashlib.sha256()
        # Hash the id and ru
        h.update(self.id.encode('utf-8'))
        h.update(str(ru).encode('utf-8'))

        return int.from_bytes(h.digest(), 'big')

    def is_valid_keypair(self):
        return validate_key_pair(
            self.public_key,
            self.private_key,
            self.g,
            self.p
        )

    def get_registration_request(self):
        return RegisterCertificateRequest(self.id, self.public_key)

    def get_authentication_request(self):
        return AuthenticationRequest(self.certificate.public_key, self.certificate.commitment,self.certificate.signature)

    def get_authentication_commitment_request(self, s, V, certificates: List[Certificate]):
        U = pow(self.g, s, self.p)
        for i in range(len(V)):
            U = (U * pow(certificates[i].public_key, V[i], self.p)) % self.p

        return AuthenticationCommitmentRequest(U)

    def get_authentication_verification_request(self, s, c,V: List[int], certificates: List[Certificate]):

        vp = V[0]
        for i in range(1, len(V)):
            vp ^= V[i]
        vp ^= c

        pos = random.randint(0, self.certificates_n-1)
        V.insert(pos, vp)
        certificates.insert(pos, self.certificate)

        r = (s - (self.private_key * vp)) % self.q

        return AuthenticationVerificationRequest(r, V, certificates)

    def verify_authentication_request(self, c, U, verification_request: AuthenticationVerificationRequest):

        for cert in verification_request.certificates:
            if not self.validate_certificate(cert):
                print(f"[Node {self.port}] Invalid certificate found during verification")
                return False

        c_hat = verification_request.V[0]
        for i in range(1, len(verification_request.V)):
            c_hat ^= verification_request.V[i]

        if c_hat - c != 0:
            print(f"[Node {self.port}] Verification failed: c_hat != c")
            return False

        U_hat = pow(self.g, verification_request.r, self.p)
        for i in range(len(verification_request.V)):
            U_hat = (U_hat * pow(verification_request.certificates[i].public_key, verification_request.V[i], self.p)) % self.p

        if U_hat != U:
            print(f"[Node {self.port}] Verification failed: U_hat - U")
            return False

        else:
            print(f"[Node {self.port}] Verification successful: c_hat == c and U_hat == U")
            return True


    def validate_certificate(self, certificate: Certificate) -> bool:
        return validate.validate_certificate(certificate, self.p, self.q, self.g, self.ca_public_key)

    def _get_node_status(self):
        """Returns the status of the node including its IP, port, and public key."""
        return f"{self.ip}:{self.port}: {self.zkp.public}"

    def register_with_bootstrap(self, bootstrap_ip, bootstrap_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((bootstrap_ip, bootstrap_port))
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
                sender_port = parts[2]
                cert = pickle.loads(bytes.fromhex(parts[3]))

                # Verificação da assinatura do certificado
                if not self.validate_certificate(cert):  # você precisará dessa função no CA
                    print(f"[Node {self.port}] Certificado inválido de {sender_port}")
                    conn.send("FAIL".encode())
                    conn.close()
                    return

                peer_public = cert.public_key

                if peer_public is None:
                    print(f"[Node {self.port}] No public key found for peer {addr}")
                    conn.send("FAIL".encode())
                    conn.close()
                    continue
                
                challenge = random.randint(1, 2**128)
                conn.send(str(challenge).encode())
                
                s_recv = int(conn.recv(4096).decode())
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
            start = time.time()
            self.monitor.log_sent(self.port)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((peer_ip, int(peer_port)))
                R = self.zkp.create_commitment()

                cert_hex = pickle.dumps(self.certificate).hex()
                s.send(f"AUTH|{R}|{self.port}|{cert_hex}".encode())

                challenge = int(s.recv(4096).decode())
                s_value = self.zkp.compute_response(challenge)
                s.send(str(s_value).encode())

                result = s.recv(4096).decode()
                print(f"[Node {self.port}] Authentication result: {result}")
                if result == "OK":
                    s.send(message.encode())
                    print(f"[Node {self.port}] Authenticated and sent message")
                    self.monitor.log_result(self.port, True, time.time() - start)
                else:
                    print(f"[Node {self.port}] Authentication failed")
                    self.monitor.log_result(self.port, False, time.time() - start)
        except Exception as e:
            print(f"[Node {self.port}] Connection failed: {e}")


    def send_attack(self, peer_ip, peer_port, attack_type: str):
        try:
            start = time.time()
            self.monitor.log_sent(self.port, is_attack=True)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((peer_ip, int(peer_port)))

                if attack_type == "replay":
                    # Executa ZKP uma vez para obter valores válidos
                    R = self.zkp.create_commitment()
                    challenge = random.randint(1, 2**128)
                    s_value = self.zkp.compute_response(challenge)

                    # Reutiliza R e s com novo challenge (o que invalida a segurança)
                    cert_hex = pickle.dumps(self.certificate).hex()
                    s.send(f"AUTH|{R}|{self.port}|{cert_hex}".encode())

                    actual_challenge = int(s.recv(4096).decode())
                    s.send(str(s_value).encode())  # usa s antigo, não s com base no novo challenge

                elif attack_type == "spoof":
                    # Usa certificado verdadeiro, mas com chave falsa
                    R = self.zkp.create_commitment()

                    # Falsifica chave pública (ex: +1 na real)
                    spoof_cert = Certificate(public_key=self.certificate.public_key + 1,
                                             commitment=self.certificate.r,
                                             signature=self.certificate.signature)
                    cert_hex = pickle.dumps(spoof_cert).hex()
                    s.send(f"AUTH|{R}|{self.port}|{cert_hex}".encode())

                    challenge = int(s.recv(4096).decode())
                    s_value = self.zkp.compute_response(challenge)
                    s.send(str(s_value).encode())

                else:
                    print(f"[Node {self.port}] Tipo de ataque desconhecido: {attack_type}")
                    return

                result = s.recv(4096).decode()
                if result == "OK":
                    self.monitor.log_result(self.port, True, time.time() - start, is_attack=True)
                    print(f"[Node {self.port}] Ataque {attack_type} foi aceito (inseguro!)")
                else:
                    self.monitor.log_result(self.port, False, time.time() - start, is_attack=True)
                    print(f"[Node {self.port}] Ataque {attack_type} corretamente rejeitado")

        except Exception as e:
            print(f"[Node {self.port}] Falha no ataque {attack_type} para {peer_port}: {e}")


    # def request_certificate(self, CA_HOST=None, CA_PORT=None) -> bool:
    #     """Request certificate from CA server"""
    #     try:
    #         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #             s.connect((CA_HOST, CA_PORT))
    #
    #             request = CARequest(
    #                 type="REGISTER",
    #                 data=RegisterCertificateRequest(self.id, self.public_key)
    #             )
    #
    #             s.send(pickle.dumps(request))
    #             response = s.recv(4096)
    #             self.certificate = pickle.loads(response)
    #             return True
    #
    #     except Exception as e:
    #         print(f"[Node {self.port}] Failed to get certificate: {e}")
    #         return False
    #