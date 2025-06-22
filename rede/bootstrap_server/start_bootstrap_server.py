import argparse
import asyncio
import random
import secrets

from rede.bootstrap_server.bootstrap_server import BootstrapServer
from rede.ca.ca import CertificateAuthority
from rede.models.ca_models import RegisterCertificateRequest
from rede.zkp import get_encrypting_values


async def main():
    parser = argparse.ArgumentParser(description='Start the Bootstrap Server')
    parser.add_argument('--host', default='127.0.0.1', help='Host address')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    args = parser.parse_args()

    print("Generating cryptographic parameters...")
    p, q, g = get_encrypting_values()
    ca = CertificateAuthority(p, q, g)
    ca_public_key = ca.get_ca_public_key()

    bootstrap = BootstrapServer(args.host, args.port, ca_public_key, p, q, g)

    print("Mocking certificates...")
    for i in range(1, 11):
        mock_id = f"mock_node_{i}"
        mock_public_key = pow(g, secrets.randbelow(q), p)

        sign_request = RegisterCertificateRequest(mock_id, mock_public_key)
        cert = ca.sign_public_key(sign_request)
        bootstrap.certificates.add(cert)

    try:
        await bootstrap.start_async()
    except KeyboardInterrupt:
        await bootstrap.stop_async()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Bootstrap] Received interrupt signal, shutting down...")