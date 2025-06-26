import asyncio
import pickle
import random
from typing import Set
from rede.models.ca_models import Certificate
from rede.utils import validate


class BootstrapServer:
    def __init__(self, host: str, port: int, ca_public_key: int, p: int, q: int, g: int):
        self.host = host
        self.port = port
        self.certificates: Set[Certificate] = set()
        self.connected_nodes: Set[int] = set()# {node_id: (ip, port)}
        self.ca_public_key = ca_public_key
        self.p = p
        self.q = q
        self.g = g
        self.server = None
        self.running = False

    def validate_certificate(self, certificate: Certificate) -> bool:
        return validate.validate_certificate(
            certificate, self.p, self.q, self.g, self.ca_public_key
        )

    async def start_async(self):
        """Start the bootstrap server"""

        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            reuse_address=True
        )
        self.running = True

        print(f"[Bootstrap] Server started on {self.host}:{self.port}")
        print(f"[Bootstrap] CA Public Key: {self.ca_public_key}")
        print(f"[Bootstrap] Parameters: p={self.p}, q={self.q}, g={self.g}")

        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connections"""
        address = writer.get_extra_info('peername')
        try:
            data = await reader.read(4096)
            if not data:
                return

            data_parts = data.decode().split("|")
            request_type = data_parts[0]

            print(f"[Bootstrap]Received request: {request_type}")

            if request_type == "AUTH":
                if len(data_parts) != 3:
                    raise ValueError("Invalid authentication format")

                print(f"[Bootstrap] Authentication request received from", address)
                client_port = data_parts[1]
                authenticate_request = pickle.loads(bytes.fromhex(data_parts[2]))

                R = authenticate_request.commitment
                signature = authenticate_request.signature
                public_key = authenticate_request.public_key

                certificate = Certificate(public_key=public_key, commitment=R, signature=signature)
                is_valid = self.validate_certificate(certificate)
                print(f"[Bootstrap] Certificate from {client_port} is valid: {is_valid}")
                if is_valid:
                    print(f"[Bootstrap] Validated for {client_port}")

                    writer.write("OK".encode())
                    await writer.drain()

                    self.certificates.add(certificate)
                    self.connected_nodes.add(int(client_port))
                    print(f"[Bootstrap] New peer authenticated: {client_port}")
                    print(f"[Bootstrap] Authenticated succeeded for port {client_port}")

                else:
                    writer.write("FAILED".encode())
                    await writer.drain()
                    print(f"[Bootstrap] Authentication failed for {client_port}")


            elif request_type == "REQUEST_CERTIFICATES":
                await self._handle_certificate_request(reader, writer, int(data_parts[1]), int(data_parts[2]))
            else:
                writer.write(b"INVALID_REQUEST")
                await writer.drain()

        except Exception as e:
            print(f"[Bootstrap] Error handling client {address}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _handle_certificate_request(self, reader: asyncio.StreamReader,
                                          writer: asyncio.StreamWriter,
                                          port: int, k: int):
        """Handle certificate list requests"""
        try:
            print(f"[Bootstrap] Certificate request from port {port} for {k} certificates")

            if port in self.connected_nodes:
                certificates_to_send = random.sample(list(self.certificates), min(k, len(self.certificates)))

                buffer = pickle.dumps(certificates_to_send)
                writer.write(buffer)
                await writer.drain()
                print(f"[Bootstrap] Sent {len(certificates_to_send)} certificates to {port}")
            else:
                writer.write(b"UNAUTHENTICATED")
                await writer.drain()
                print(f"[Bootstrap] Peer {port} is not authenticated")

        except (IndexError, ValueError) as e:
            print(f"[Bootstrap] Invalid certificate request from {port}: {e}")
            writer.write(b"INVALID_REQUEST")
            await writer.drain()

    async def stop_async(self):
        """Stop the bootstrap server"""
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print("[Bootstrap] Server stopped")