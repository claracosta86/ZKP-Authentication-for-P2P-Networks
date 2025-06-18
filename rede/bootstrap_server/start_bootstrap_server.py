import argparse
from rede.bootstrap_server.bootstrap_server import BootStrapServer
from rede.ca.ca import CertificateAuthority
from rede.zkp import get_encrypting_values


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Start the Bootstrap Server')
    parser.add_argument('--ip', default='127.0.0.1', help='IP address to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to listen on')
    args = parser.parse_args()

    # Generate cryptographic parameters
    print("Generating cryptographic parameters...")
    p, q, g= get_encrypting_values()
    # Initialize CA
    ca = CertificateAuthority(p, q, g)
    ca_public_key = ca.get_ca_public_key()

    print(f"Starting Bootstrap Server on {args.ip}:{args.port}")
    print(f"CA Public Key: {ca_public_key}")
    print(f"Parameters: p={p}, q={q}, g={g}")

    # Create and start bootstrap server
    bootstrap = BootStrapServer(args.ip, args.port, ca_public_key, p, q, g)
    bootstrap.start()


if __name__ == "__main__":
    main()