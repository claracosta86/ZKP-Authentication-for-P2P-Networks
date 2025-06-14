import hashlib
import secrets

from rede.models.ca_models import RegisterCertificateRequest, Certificate


class CertificateAuthority:
    def __init__(self, p: int, Q: int, g: int):
        self.p = p
        self.Q = Q
        self.g = g
        self.ca_private_key = secrets.randbelow(Q)
        self.ca_public_key = pow(self.g, self.ca_private_key, self.p)

    def sign_public_key(self, request: RegisterCertificateRequest) -> Certificate:
        """
        Signs a user's public key to create a certificate using Schnorr signature scheme.

        Args:
            request (RegisterCertificateRequest): Contains user's ID and public key

        Returns:
            Certificate: A certificate containing the public key and signature (r,s)
        """
        k = secrets.randbelow(self.Q)  # random nonce
        r = pow(self.g, k, self.p)  # r = g^k mod p

        # e = H(public_key || r) mod Q
        e = int.from_bytes(hashlib.sha256(str(request.public_key).encode() + str(r).encode()).digest(), 'big') % self.Q

        # s = k + ca_private_key * e mod Q
        s = (k + self.ca_private_key * e) % self.Q

        return Certificate(request.public_key, r, s)

    def get_ca_public_key(self):
        # Public key of CA: Ks_pub = g^Ks mod p
        return self.ca_public_key
