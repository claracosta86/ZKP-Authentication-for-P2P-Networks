import rede.config
from rede import config
from rede.ca.ca import CertificateAuthority
from rede.models.ca_models import Certificate
from rede.monitor import Monitor
from rede.node.node import Node
from rede.zkp import get_encrypting_values


def main():

    p, q, g= get_encrypting_values()

    port = 6000
    ca = CertificateAuthority(p, q, g)

    user = Node('127.0.0.1', port, config.BOOTSTRAP_NODE, config.BOOTSTRAP_PORT, p, q, g, Monitor(), ca.get_ca_public_key())
    request = user.get_registration_request()

    # Server side
    cert = ca.sign_public_key(request)
    user.set_certificate(cert)

    print("User ID:", request.id)
    print("User Public Key:", request.public_key)
    print("Certificate:", cert)
    print("CA Public Key (g^Ks mod p):", ca.get_ca_public_key())

    print("Should be valid certificate: ", user.validate_certificate(cert))
    print("Should be invalid certificate: ", user.validate_certificate(Certificate(request.public_key, 12, 34)))

if __name__ == "__main__":
    main()