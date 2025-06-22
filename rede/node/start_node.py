import argparse
import asyncio
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from rede.monitor import Monitor
from rede.node.node import Node
from rede.node.node_peer import NodePeer
from rede.zkp import get_encrypting_values

async def main():
    parser = argparse.ArgumentParser(description='Start a Node')
    parser.add_argument('--host', default='127.0.0.1', help='Host address')
    parser.add_argument('--port', type=int, required=True, help='Node port')
    parser.add_argument('--ca-host', default='127.0.0.1', help='CA host address')
    parser.add_argument('--ca-port', type=int, default=5001, help='CA port')
    parser.add_argument('--peers', default='', help='Peer list (ip:port:pubkey;...)')
    args = parser.parse_args()

    # Get system parameters
    p, q, g = get_encrypting_values()

    # Create node
    node = Node(
        args.host,
        args.port,
        args.ca_host,
        args.ca_port,
        p, q, g,
        Monitor()
    )

    # Create node peer server
    node_peer = NodePeer(node, args.host, args.port)

    await asyncio.sleep(1)  # wait for the node to initialize
    try:
        if not node.request_certificate(args.ca_host, args.ca_port):
            print(f"[Node {args.port}] Failure requesting certificate from CA")
            return
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