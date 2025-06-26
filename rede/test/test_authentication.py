import asyncio
import random
import secrets
import statistics

from rede.bootstrap_server.bootstrap_server import BootstrapServer
from rede.ca.ca import CertificateAuthority
from rede.models.ca_models import RegisterCertificateRequest
from rede.node.node import Node
from rede.node.node_peer import NodePeer
from rede.monitor import Monitor
from rede.zkp import get_encrypting_values


async def run_authentication_test(num_nodes=3, iterations=5, num_certs = 5):
    """
    Run authentication test between multiple nodes.

    Args:
        num_nodes: Number of nodes to create
        iterations: Number of authentication attempts per node pair
        num_certs: Number of certificates each node should have
    """
    # Cryptographic parameters
    p,q,g = get_encrypting_values()

    ca = CertificateAuthority(p, q, g)

    # Create monitor
    monitor = Monitor()

    # Create nodes
    host = '127.0.0.1'
    base_port = 8000
    nodes = []
    node_peers = []

    mock_certs = set()
    for i in range(1, 11):
        mock_id = f"mock_node_{i}"
        mock_public_key = pow(g, secrets.randbelow(q), p)

        sign_request = RegisterCertificateRequest(mock_id, mock_public_key)
        mock_certs.add(ca.sign_public_key(sign_request))

    bootstrap_server = BootstrapServer(host, base_port, ca.get_ca_public_key(), p, q, g)
    bootstrap_server.certificates = mock_certs
    asyncio.create_task(bootstrap_server.start_async())

    # Create common nodes
    for i in range(1, num_nodes):
        port = base_port + i
        node = Node(host, port, host, base_port, p, q, g, monitor, ca.get_ca_public_key())
        node.set_certificate(ca.sign_public_key(node.get_registration_request()))
        node.set_certificates(random.sample(list(mock_certs), k=min(len(mock_certs), num_certs)))

        node_peer = NodePeer(node, host, port, commands_allowed=False)

        nodes.append(node)
        node_peers.append(node_peer)

    # Start all nodes
    start_tasks = []
    for peer in node_peers:
        # Start node and handle potential errors
        try:
            task = asyncio.create_task(peer.start_async())
            start_tasks.append(task)
        except Exception as e:
            print(f"Error starting peer: {e}")
            raise

    await asyncio.sleep(3)
    print("All nodes started successfully.")
    # Additional wait to ensure all nodes are stable

    # Run authentication tests
    for _ in range(iterations):
        for i in range(0, len(node_peers)):
            for j in range(i + 1, len(node_peers)):
                # Authenticate in both directions
                await node_peers[i].perform_authentication(node_peers[j].port)
                await node_peers[j].perform_authentication(node_peers[i].port)

    # Calculate statistics
    latencies = monitor.latencies
    avg_latency = statistics.mean(latencies) if latencies else 0
    std_dev = statistics.stdev(latencies) if len(latencies) > 1 else 0

    print(f"\nAuthentication Test Results:")
    print(f"Total authentications: {len(latencies)}")
    print(f"Average latency: {avg_latency:.4f} seconds")
    print(f"Standard deviation: {std_dev:.4f} seconds")
    print(f"Min latency: {min(latencies):.4f} seconds")
    print(f"Max latency: {max(latencies):.4f} seconds")

    # Stop all nodes
    for peer in node_peers:
        await peer.stop_async()


# Run the test
if __name__ == "__main__":
    asyncio.run(run_authentication_test(num_nodes=4, iterations=3))