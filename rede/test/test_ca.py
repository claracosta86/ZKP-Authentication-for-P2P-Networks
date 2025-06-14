from rede import config
from rede.ca.ca import CertificateAuthority
from rede.node import VehicleNode
from rede.zkp import PrimeGenerator

def main():

    p, q = PrimeGenerator.generate_safe_prime(bits=256)
    g = PrimeGenerator.find_generator(p, q)

    port = 6000
    ca = CertificateAuthority(p, q, g)

    user = VehicleNode('127.0.0.1', port, config.BOOTSTRAP_NODE, config.BOOTSTRAP_PORT, ca.get_ca_public_key() ,p, q, g)
    request = user.get_registration_request()

    # Server side
    cert = ca.sign_public_key(request)
    user.set_certificate(cert)

    print("User ID:", request.id)
    print("User Public Key:", request.public_key)
    print("Certificate:", cert)
    print("CA Public Key (g^Ks mod p):", ca.get_ca_public_key())

    print("Is valid certificate ?", user.validate_certificate(cert))

if __name__ == "__main__":
    main()