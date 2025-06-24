import hashlib
import secrets

from rede.models.ca_models import RegisterCertificateRequest, Certificate


class CertificateAuthority:
    def __init__(self, p: int, q: int, g: int):
        self.p = p
        self.q = q
        self.g = g
        self.ca_private_key = 123456789
        self.ca_public_key = pow(self.g, self.ca_private_key, self.p)

    def sign_public_key(self, request: RegisterCertificateRequest) -> Certificate:
        """
        Signs a user's public key to create a certificate using Schnorr signature scheme.
        """
        k = secrets.randbelow(self.q)  # random nonce
        r = pow(self.g, k, self.p)  # r = g^k mod p

        # Convert integers to fixed-width bytes
        pub_key_bytes = request.public_key.to_bytes(256, 'big')
        r_bytes = r.to_bytes(256, 'big')

        # e = H(public_key || r) mod q
        e = int.from_bytes(hashlib.sha256(pub_key_bytes + r_bytes).digest(), 'big') % self.q

        # s = (k + e * Ks) mod q
        s = (k + self.ca_private_key * e) % self.q

        return Certificate(request.public_key, r, s)

    def get_ca_public_key(self):
        # Public key of CA: Ks_pub = g^Ks mod p
        return self.ca_public_key
