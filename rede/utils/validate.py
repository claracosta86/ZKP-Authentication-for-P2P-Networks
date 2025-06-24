import hashlib

from rede.models.ca_models import Certificate

def validate_certificate(certificate: Certificate, p: int, q: int, g: int, ca_public_key: int) -> bool:
    """
    Validates a certificate using Schnorr signature verification.

    Args:
        certificate (Certificate): The certificate to validate, containing the public key, r, and s values.
        p (int): A large prime number used as the modulus in the Schnorr signature scheme.
        q (int): A prime divisor of p-1, representing the order of the subgroup.
        g (int): A generator of the subgroup of order q in the multiplicative group modulo p.
        ca_public_key (int): The public key of the Certificate Authority (CA) used for validation.

    Returns:
        bool: True if the certificate is valid, False otherwise.
    """
    # Convert integers to fixed-width bytes
    pub_key_bytes = certificate.public_key.to_bytes(256, byteorder='big')
    r_bytes = certificate.commitment.to_bytes(256, byteorder='big')

    # Concatenate bytes directly
    e = int.from_bytes(hashlib.sha256(pub_key_bytes + r_bytes).digest(), 'big') % q

    left = pow(g, certificate.signature, p)
    right = (certificate.commitment * pow(ca_public_key, e, p)) % p

    return left == right


def validate_key_pair(public_key: int, private_key: int, g: int, p: int) -> bool:
    """
    Validates if a public key was generated from a private key.

    Args:
        public_key: The public key y
        private_key: The private key x
        g: The generator
        p: The prime modulus

    Returns:
        bool: True if the key pair is valid, False otherwise
    """
    computed_public = pow(g, private_key, p)
    return (computed_public - public_key) % p == 0