import argparse
import asyncio
import sys
from rede.zkp import get_encrypting_values
from rede.ca.ca_server import CAServer

async def main():
    parser = argparse.ArgumentParser(description='Start the CA Server')
    parser.add_argument('--host', default='127.0.0.1', help='Host address')
    parser.add_argument('--port', type=int, default=5001, help='Port number')
    args = parser.parse_args()

    # Get system parameters
    p, q, g = get_encrypting_values()

    # Create and start CA server
    ca_server = CAServer(args.host, args.port, p, q, g)

    try:
        server_task = asyncio.create_task(ca_server.start_async())
        await server_task

    except Exception as e:
        print(f"[CA] Error: {e}")
    finally:
        if ca_server.running:
            await ca_server.stop_async()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[CA] Received interrupt signal, shutting down...")
        sys.exit(0)