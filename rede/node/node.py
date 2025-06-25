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
        self.peers_authenticated_in = []

        self.p = p
        self.q = q
        self.g = g
        self.private_key = self.init_private_key() # private key
        self.public_key = pow(self.g, self.private_key, self.p)

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
