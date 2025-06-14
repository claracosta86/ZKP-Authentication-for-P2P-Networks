import threading
import time
from network import BootstrapServer
from node import VehicleNode
import config as config
from rede.ca import CertificateAuthority
from zkp import PrimeGenerator

def main():
    # Gera p, q, g uma única vez para todos os nós
    p, q = PrimeGenerator.generate_safe_prime(bits=256)
    g = PrimeGenerator.find_generator(p, q)

    ca = CertificateAuthority(p, q, g)

    # Start bootstrap server
    bootstrap = BootstrapServer(config.BOOTSTRAP_NODE, config.BOOTSTRAP_PORT)
    threading.Thread(target=bootstrap.start, daemon=True).start()

    time.sleep(1)

    # Start nodes
    nodes = []
    for i in range(config.TOTAL_NODES):
        port = config.MESSAGE_PORT_START + i
        node = VehicleNode('127.0.0.1', port, config.BOOTSTRAP_NODE, config.BOOTSTRAP_PORT, ca.get_ca_public_key(), p, q, g)
        cert = ca.sign_public_key(node.get_registration_request())
        node.set_certificate(cert)
        node.register_with_bootstrap()
        threading.Thread(target=node.listen, daemon=True).start()
        nodes.append(node)

    time.sleep(2)

    # Send authenticated messages between random peers
    for node in nodes:
        for peer_ip, peer_port in node.peers:
            node.send_authenticated_message(peer_ip, peer_port, f"Secure hello from {node.port}")
            time.sleep(0.5)

    time.sleep(5)

if __name__ == "__main__":
    main()