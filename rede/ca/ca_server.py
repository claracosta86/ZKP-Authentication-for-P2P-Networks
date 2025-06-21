import asyncio
import pickle
from dataclasses import dataclass
from typing import Any
from aioconsole import ainput

from rede.ca.ca import CertificateAuthority

@dataclass
class CARequest:
    """Certificate Authority request format"""
    type: str  # e.g., 'REGISTER'
    data: Any  # e.g., RegisterCertificateRequest instance


class CAServer:
    def __init__(self, host: str, port: int, p: int, q: int, g: int):
        self.host = host
        self.port = port
        self.ca = CertificateAuthority(p, q, g)
        self.server = None
        self.running = False

    async def start_async(self):
        """Start the CA server and command handler"""
        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            reuse_address=True
        )
        self.running = True

        print(f"[CA] Server started on {self.host}:{self.port}")
        print(f"[CA] Public Key: {self.ca.get_ca_public_key()}")

        async with self.server:
            server_task = asyncio.create_task(self.server.serve_forever())
            input_task = asyncio.create_task(self.handle_input())

            # Wait for either task to complete
            try:
                _, pending = await asyncio.wait(
                    [server_task, input_task],
                    return_when=asyncio.FIRST_COMPLETED
                )
                # Cancel remaining tasks
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            except Exception as e:
                print(f"[CA] Error: {e}")
            finally:
                if self.running:
                    await self.stop_async()

    async def handle_input(self):
        """Handle terminal commands"""
        print("[CA] Available commands: status, quit")

        while self.running:
            try:
                command = await ainput("Enter command: ")
                command = command.strip().lower()

                if not command:
                    continue

                if command in {"quit", "exit"}:
                    print("[CA] Shutting down...")
                    await self.stop_async()
                    break
                elif command == "status":
                    print(f"[CA] Server is running on {self.host}:{self.port}")
                    print(f"[CA] Public Key: {self.ca.get_ca_public_key()}")
                else:
                    print("[CA] Unknown command. Available commands: status, quit")

            except Exception as e:
                print(f"[CA] Input error: {e}")
                break

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle client connections and requests asynchronously"""
        address = writer.get_extra_info('peername')
        try:
            data = await reader.read(4096)
            if not data:
                print(f"[CA] Empty request from {address}")
                return

            request = pickle.loads(data)

            if not isinstance(request, CARequest):
                raise ValueError("Invalid request format")

            if request.type == "REGISTER":
                certificate = self.ca.sign_public_key(request.data)
                response = pickle.dumps(certificate)
                writer.write(response)
                await writer.drain()
                print(f"[CA] Issued certificate to {address}")
            else:
                print(f"[CA] Unknown request type from {address}: {request.type}")

        except Exception as e:
            print(f"[CA] Error handling client {address}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def stop_async(self):
        """Stop the CA server asynchronously"""
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print("[CA] Server stopped")