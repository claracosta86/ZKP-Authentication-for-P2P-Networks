import asyncio
import pickle
import random
from aioconsole import ainput

from rede.models.ca_models import Certificate
from rede.node.node import Node


class NodePeer:
    def __init__(self, node: Node, host: str, port: int):
        self.node = node
        self.host = host
        self.port = port
        self.server = None
        self.running = False
        self.k = 5 # number of certificates to get from bootstrap server

    async def start_async(self):
        """Start the node peer server and command handler"""
        self.server = await asyncio.start_server(
            self._handle_client,
            self.host,
            self.port,
            reuse_address=True
        )
        self.running = True

        print(f"[Node {self.port}] Server started on {self.host}:{self.port}")

        async with self.server:
            server_task = asyncio.create_task(self.server.serve_forever())
            input_task = asyncio.create_task(self.handle_input())
            await self.authenticate_to_bootstrap_and_get_certificates()
            try:
                _, pending = await asyncio.wait(
                    [server_task, input_task],
                    return_when=asyncio.FIRST_COMPLETED
                )
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass
            except Exception as e:
                print(f"[Node {self.port}] Error: {e}")
            finally:
                if self.running:
                    await self.stop_async()

    async def handle_input(self):
        """Handle terminal commands"""
        print(f"[Node {self.port}] Available commands:  authenticate <port>, send <port> <message>, status, quit")

        while self.running:
            try:
                command = await ainput("Enter command: \n")
                if not command:
                    continue

                parts = command.strip().split()
                cmd = parts[0].lower()

                if cmd in {"quit", "exit"}:
                    print(f"[Node {self.port}] Shutting down...")
                    await self.stop_async()
                    break
                elif cmd == "status":
                    print(f"[Node {self.port}] Running on {self.host}:{self.port}")
                    if self.node.zkp:
                        print(f"[Node {self.port}] ZKP Public Key: {self.node.zkp.public}")

                elif cmd == "authenticate":
                    if len(parts) != 2:
                        print("[Node] Usage: authenticate <port>")
                        continue

                    peer_port = int(parts[1])
                    request = pickle.dumps(self.node.get_authentication_request()).hex()
                    await self.send_message_async(self.host, peer_port, f"AUTH|{self.port}|{request}")

                elif cmd == "send" and len(parts) >= 3:
                    peer_port = int(parts[1])
                    message = " ".join(parts[2:])
                    await self.send_message_async(self.host, peer_port, message)
                else:
                    print(f"[Node {self.port}] Unknown command. Available: send <port> <message>, status, quit")

            except Exception as e:
                print(f"[Node {self.port}] Input error: {e}")
                break

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connections"""
        address = writer.get_extra_info('peername')
        try:
            data = await reader.read(4096)
            if not data:
                return

            data_parts = data.decode().split("|")
            if data_parts[0] == "AUTH":
                if len(data_parts) != 3:
                    raise ValueError("Invalid authentication format")

                print(f"[Node {self.port}] Authentication request received from", address)
                client_port = data_parts[1]
                authenticate_request = pickle.loads(bytes.fromhex(data_parts[2]))

                R = authenticate_request.commitment
                signature = authenticate_request.signature
                public_key = authenticate_request.public_key

                # Send challenge
                challenge = random.randint(1, 2**128)
                writer.write(str(challenge).encode())
                await writer.drain()
                
                # Get response
                s_data = await reader.read(4096)
                s_value = int(s_data.decode())

                # Verify
                if self.node.zkp.verify_proof(public_key, R, challenge, s_value):
                    print(f"CA public key: {self.node.ca_public_key}")
                    is_valid = self.node.validate_certificate(Certificate(public_key, R, signature))
                    print(f"[Node {self.port}] Certificate valid: {is_valid}")
                    if is_valid:
                        print(f"[Node {self.port}] Validated for {address}")

                        writer.write("OK".encode())
                        await writer.drain()
                        print(f"[Node {self.port}] Authenticated succeeded for port {address}")

                    else:
                        writer.write("FAILED".encode())
                        await writer.drain()
                        print(f"[Node {self.port}] Authentication failed for {address}")
                   
                    writer.write("OK".encode())
                    await writer.drain()
                    print(f"[Node {self.port}] ZKP Authentication succeeded for port {address}")
                else:
                    writer.write("FAILED".encode())
                    await writer.drain()
                    print(f"[Node {self.port}] ZKP Authentication failed for {address}")

            else:
                message = data.decode()
                print(f"[Node {self.port}] Message received from {address}:\n{message}")

                # Authomatically acknowledge the message
                response = f"Acknowledged message:\n{message}"
                writer.write(response.encode())
                await writer.drain()

        except Exception as e:
            print(f"[Node {self.port}] Error handling client {address}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def send_message_async(self, peer_ip: str, peer_port: int, message: str):
        """Send a message to another peer"""
        try:
            reader, writer = await asyncio.open_connection(peer_ip, peer_port)

            writer.write(message.encode())
            await writer.drain()
            print(f"[Node {self.port}] Message sent to {peer_port}")

            # Wait for a response
            response = await reader.read(4096)
            print(f"[Node {self.port}] Response from {peer_port}: {response.decode()}")

        except Exception as e:
            print(f"[Node {self.port}] Connection failed: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def authenticate_to_bootstrap_and_get_certificates(self):
        """Authenticate with the bootstrap server and retrieve certificates"""
        try:
            # Send authentication request to the bootstrap server
            request = pickle.dumps(self.node.get_authentication_request()).hex()
            message = f"AUTH|{self.port}|{request}"

            reader, writer = await asyncio.open_connection(self.node.bootstrap_host, self.node.bootstrap_port)
            writer.write(message.encode())
            await writer.drain()

            # Wait for response
            challenge_data = await reader.read(1024)
            challenge = int(challenge_data.decode())

            s = self.node.zkp.compute_response(challenge)
            writer.write(str(s).encode())
            await writer.drain()

            response = await reader.read(1024)
            response_message = response.decode()
            if response_message == "OK":
                print(f"[Node {self.port}] Successfully authenticated with bootstrap server")
            elif response_message == "FAILED":
                print(f"[Node {self.port}] Authentication failed with bootstrap server")
                return
            else:
                print(f"[Node {self.port}] Unexpected response from bootstrap server: {response_message}")
                return

            # Request certificates
            message = f"REQUEST_CERTIFICATES|{self.port}|{self.k}"
            reader, writer = await asyncio.open_connection(self.node.bootstrap_host, self.node.bootstrap_port)

            writer.write(message.encode())
            await writer.drain()

            certificates_data = await reader.read(4096)
            certificates = pickle.loads(certificates_data)
            self.node.set_certificates(certificates)
            print(f"[Node {self.port}] Certificates retrieved from bootstrap server")

        except Exception as e:
            print(f"[Node {self.port}] Error during bootstrap authentication: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def stop_async(self):
        """Stop the node peer server"""
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            print(f"[Node {self.port}] Node stopped")
