import argparse
import asyncio
import random
import sys

from rede.ca.ca import CertificateAuthority
from rede.monitor import Monitor
from rede.node.node import Node
from rede.node.node_peer import NodePeer
from rede.zkp import get_encrypting_values


async def main():
    parser = argparse.ArgumentParser(description='Start a Node')
    parser.add_argument('--host', default='127.0.0.1', help='Host address')
    parser.add_argument('--port', type=int, required=True, help='Node port')
    parser.add_argument('--bootstrap-host', default='127.0.0.1', help='Bootstrap server host address')
    parser.add_argument('--bootstrap-port', type=int, default=5000, help='Bootstrap server port')
    parser.add_argument('--peers', default='', help='Peer list (ip:port:pubkey;...)')
    parser.add_argument('--attacker', action='store_true', help='Run the node as an attacker')
    args = parser.parse_args()

    # Get system parameters
    p, q, g = get_encrypting_values()
    ca = CertificateAuthority(p, q, g)

    # Create node
    node = Node(
        args.host,
        args.port,
        args.bootstrap_host,
        args.bootstrap_port,
        p, q, g,
        Monitor(),
        ca.get_ca_public_key(),
        5
    )

    # Create node peer server
    node_peer = NodePeer(node, args.host, args.port, commands_allowed = True)

    try:
        # Register with CA first
        cert = ca.sign_public_key(node.get_registration_request())
        node.set_certificate(cert)

        if args.attacker:
            node.private_key = random.randint(1, 1000000)

        print(f"[Node {args.port}] Certificate obtained from CA")

        # Start node server
        await node_peer.start_async()

    except Exception as e:
        print(f"[Node {args.port}] Error: {e}")
        if node_peer.running:
            await node_peer.stop_async()
        sys.exit(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Node] Received interrupt signal, shutting down...")
        sys.exit(0)