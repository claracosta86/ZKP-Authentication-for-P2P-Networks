import asyncio
import csv
import random
import secrets
import statistics
from pathlib import Path

from rede.bootstrap_server.bootstrap_server import BootstrapServer
from rede.ca.ca import CertificateAuthority
from rede.models.ca_models import RegisterCertificateRequest
from rede.node.node import Node
from rede.node.node_peer import NodePeer
from rede.monitor import Monitor
from rede.zkp import get_encrypting_values


async def run_authentication_test(num_nodes=10, iterations=5, num_certs = 5, outuput_file='output/authentication_results.csv'):
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
    for i in range(1, num_certs* num_nodes):
        mock_id = f"mock_node_{i}"
        mock_public_key = pow(g, secrets.randbelow(q), p)

        sign_request = RegisterCertificateRequest(mock_id, mock_public_key)
        mock_certs.add(ca.sign_public_key(sign_request))

    bootstrap_server = BootstrapServer(host, base_port, ca.get_ca_public_key(), p, q, g)
    bootstrap_server.certificates = mock_certs
    asyncio.create_task(bootstrap_server.start_async())

    # Create common nodes
    for i in range(1, num_nodes+1):
        port = base_port + i
        node = Node(host, port, host, base_port, p, q, g, monitor, ca.get_ca_public_key(), certificates_number=num_certs)
        node.set_certificate(ca.sign_public_key(node.get_registration_request()))
        node.set_certificates(random.sample(list(mock_certs), k=min(len(mock_certs), num_certs)))

        node_peer = NodePeer(node, host, port, commands_allowed=False, k= num_certs)

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

    await asyncio.sleep(1)
    print("All nodes started successfully.")
    # Additional wait to ensure all nodes are stable

    # Run authentication tests
    for _ in range(iterations):
        for i in range(0, len(node_peers)):
            for j in range(i + 1, len(node_peers)):
                # Authenticate in both directions
                await node_peers[i].perform_authentication(node_peers[j].port)
                await node_peers[j].perform_authentication(node_peers[i].port)

    # Stop all nodes
    for peer in node_peers:
        await peer.stop_async()

    asyncio.create_task(bootstrap_server.stop_async())

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

    results = {
        'num_nodes': num_nodes,
        'iterations': iterations,
        'num_certs': num_certs,
        'total_authentications': len(latencies),
        'avg_latency': f"{avg_latency:.4f}",
        'std_dev': f"{std_dev:.4f}",
        'min_latency': f"{min(latencies):.4f}",
        'max_latency': f"{max(latencies):.4f}"
    }

    # Define CSV file path
    csv_file = Path(outuput_file)
    csv_file.parent.mkdir(parents=True, exist_ok=True)
    # Check if file exists to determine if we need to write headers
    file_exists = Path(csv_file).exists()

    # Write to CSV
    with open(csv_file, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results.keys())

        # Write headers only if file is new
        if not file_exists:
            writer.writeheader()

        writer.writerow(results)

# Run the test
if __name__ == "__main__":
    async def run_mass_tests():
        network_scale_test_params = [
            (2, 5, 5),
            (3, 5, 5),
            (4, 5, 5),
            (5, 5, 5),
            (6, 5, 5),
            (7, 5, 5),
            (8, 5, 5),
            (9, 5, 5),
            (10, 5, 5),
            (12, 5, 5),
            (14, 5, 5),
            (16, 5, 5),
            (18, 5, 5),
            (20, 5, 5),
            (25, 5, 5),
            (30, 5, 5),
            (35, 5, 5),
            (40, 5, 5),
        ]

        for nodes, iterations, certs in network_scale_test_params:
            print(f"\nRunning test with {nodes} nodes, {iterations} iterations, {certs} certificates")
            await run_authentication_test(nodes, iterations, certs, outuput_file= 'output/network_scale_results.csv')

        certificate_number_test_params = [
            (5, 5, 2),    # Minimal certificates
            (5, 5, 4),    # Very small scale
            (5, 5, 6),    # Small scale
            (5, 5, 8),    # Small-medium scale
            (5, 5, 10),   # Medium scale
            (5, 5, 12),   # Medium-large scale
            (5, 5, 15),   # Large scale
            (5, 5, 18),   # Very large scale
            (5, 5, 20),   # Maximum scale
            (5, 5, 25)    # Extended scale
        ]

        for nodes, iterations, certs in certificate_number_test_params:
            print(f"\nRunning test with {nodes} nodes, {iterations} iterations, {certs} certificates")
            await run_authentication_test(nodes, iterations, certs, outuput_file= 'output/certificate_number_results.csv')

    asyncio.run(run_mass_tests())