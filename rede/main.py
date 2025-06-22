import threading
import time
import os
import sys
from network import BootstrapServer

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from rede.node.node import Node
import rede.config as config
from rede.ca.ca import CertificateAuthority
from rede.zkp import get_encrypting_values
from rede.monitor import Monitor

def main():
    # Gera p, q, g uma única vez para todos os nós
    p, q, g = get_encrypting_values()
    
    ca = CertificateAuthority(p, q, g)

    # Initialize monitor de métricas
    monitor = Monitor()

    # Start bootstrap server
    bootstrap = BootstrapServer(config.BOOTSTRAP_NODE, config.BOOTSTRAP_PORT)
    threading.Thread(target=bootstrap.start, daemon=True).start()

    time.sleep(1)

    # Start nodes
    nodes = []
    for i in range(config.TOTAL_NODES):
        port = config.MESSAGE_PORT_START + i
        node = Node('127.0.0.1', port, config.BOOTSTRAP_NODE, config.BOOTSTRAP_PORT, p, q, g, monitor, ca.get_ca_public_key())
        cert = ca.sign_public_key(node.get_registration_request())
        node.set_certificate(cert)
        node.register_with_bootstrap(config.BOOTSTRAP_NODE, config.BOOTSTRAP_PORT)
        threading.Thread(target=node.listen, daemon=True).start()
        nodes.append(node)
        assert cert.public_key == node.zkp.public, f"Erro: nó {node.port} usa chave diferente da certificada!"
    time.sleep(2)

    # Send authenticated messages between random peers
    for node in nodes:
        for peer_ip, peer_port in node.peers:
            node.send_authenticated_message(peer_ip, peer_port, f"Secure hello from {node.port}")
            time.sleep(0.5)

    # Simulate replay and spoof attacks
    print("\n[ATAQUE] Iniciando simulação de ataques...\n")
    for node in nodes:
        for peer_ip, peer_port in node.peers:
            node.send_attack(peer_ip, peer_port, attack_type="replay")
            node.send_attack(peer_ip, peer_port, attack_type="spoof")
            time.sleep(0.5)

    time.sleep(5)
    monitor.report()

if __name__ == "__main__":
    main()