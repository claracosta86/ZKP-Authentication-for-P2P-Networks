import asyncio
import pickle
import random
import secrets

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
                command = await ainput("Enter command:\n")
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
                    print(f"[Node {self.port}] Certificate: {self.node.certificate}")

                elif cmd == "authenticate":
                    if len(parts) != 2:
                        print("[Node] Usage: authenticate <port>")
                        continue

                    peer_port = int(parts[1])

                    # Commitment phase

                    reader, writer = await asyncio.open_connection(self.host, peer_port)

                    chosen_certificates = random.sample(self.node.certificates, self.node.certificates_n - 1)
                    s = secrets.randbelow(self.node.q)
                    V = [secrets.randbelow(self.node.q) for _ in range(self.node.certificates_n - 1)]  # Generate n-1 random values

                    commitment = self.node.get_authentication_commitment_request(s, V, chosen_certificates)
                    print(f"[Node {self.port}] Sending authentication commitment to port {peer_port}")

                    commitment_request = pickle.dumps(commitment).hex()
                    await self.send_message_async(writer, peer_port, f"AUTH|{self.port}|{commitment_request}")

                    # Wait for challenge from prover
                    challenge_response = await reader.read(4096)
                    response_parts = challenge_response.decode().split("|")

                    if len(response_parts) != 3:
                        print(f"[Node {self.port}] Invalid response format from port {peer_port}")
                        raise ValueError("Invalid challenge response format")

                    c = int(response_parts[2])
                    # Verification phase

                    # Send verification request to prover
                    verification = self.node.get_authentication_verification_request(s, c, V, chosen_certificates)
                    verification_request = pickle.dumps(verification).hex()

                    reader, writer = await asyncio.open_connection(self.host, peer_port)
                    print(f"[Node {self.port}] Sending verification request to port {peer_port}")
                    await self.send_message_async(writer, peer_port, f"VERIFICATION|{self.port}|{verification_request}")

                    # Wait for final response
                    response = await reader.read(4096)

                    if response.decode() == "OK":
                        print(f"[Node {self.port}] Authentication succeeded with port {peer_port}")
                        self.node.peers_authenticated_at.append(peer_port)
                    elif response.decode() == "FAILED":
                        print(f"[Node {self.port}] Authentication failed with port {peer_port}")
                    else:
                        print(f"[Node {self.port}] Unexpected response from port {peer_port}")
                        raise ValueError(f"Unexpected response from port {peer_port}")

                    await writer.drain()
                    writer.close()

                elif cmd == "send" and len(parts) >= 3:
                    peer_port = int(parts[1])
                    message = " ".join(parts[2:])
                    await self.send_message_async(self.host, peer_port, message)

                else:
                    print(f"[Node {self.port}] Unknown command. Available: send <port> <message>, status, quit")

            except Exception as e:
                print(f"[Node {self.port}] Input error: {e}")


    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connections"""
        address = writer.get_extra_info('peername')
        try:

            data = await reader.readuntil(b'\n')
            data = data.strip()

            if not data:
                return

            data_parts = data.decode().split("|")
            if data_parts[0] == "AUTH":
                if len(data_parts) != 3:
                    raise ValueError("Invalid authentication format")

                prover_port = data_parts[1]
                print(f"[Node {self.port}] Authentication request received from", prover_port)

                commitment = pickle.loads(bytes.fromhex(data_parts[2]))
                U = commitment.commitment
                #Send challenge to prover
                c = secrets.randbelow(self.node.q)
                print(f"[Node {self.port}] Sending challenge to port {prover_port}")
                self.node.peer_challenges[prover_port] = c
                self.node.peer_U[prover_port] = U
                await self.send_message_async(writer, int(prover_port),f"CHALLENGE|{self.port}|{c}")

            if data_parts[0] == "VERIFICATION":
                if len(data_parts) != 3:
                    raise ValueError("Invalid verification format")

                print(f"[Node {self.port}] Verification request received from", data_parts[1])

                prover_port = data_parts[1]

                if not self.node.peer_challenges.get(prover_port) or not self.node.peer_U.get(prover_port):
                    raise ValueError(f"Authentication challenge not sent for port {prover_port}")

                verification_request = pickle.loads(bytes.fromhex(data_parts[2]))

                c = self.node.peer_challenges[prover_port]
                U = self.node.peer_U[prover_port]

                print(f"[Node {self.port}] Verifying authentication request for port {prover_port}")
                is_valid = self.node.verify_authentication_request(c, U, verification_request)

                if is_valid:
                    print(f"[Node {self.port}] Validated for {address}")

                    writer.write("OK".encode())
                    await writer.drain()
                    print(f"[Node {self.port}] Authenticated succeeded for port {address}")

                else:
                    writer.write("FAILED".encode())
                    await writer.drain()
                    print(f"[Node {self.port}] Authentication failed for {address}")

                del self.node.peer_U[prover_port]
                del self.node.peer_challenges[prover_port]
        
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

    async def send_message_async(self, writer, peer_port: int, message: str):
        """Send a message to another peer"""
        try:
            reader, writer = await asyncio.open_connection(self.host, peer_port)

            if not message.endswith('\n'):
                message += '\n'

            writer.write(message.encode())
            await writer.drain()
            print(f"[Node {self.port}] Message sent to {peer_port}")

            response = await reader.read(4096)
            print(f"[Node {self.port}] Response from {peer_port}: {response.decode()}")

        except Exception as e:
            print(f"[Node {self.port}] Connection failed: {e}")
        finally:
            if 'writer' in locals():
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
            response = await reader.read(4096)
            response_message = response.decode()

            if response_message == "OK":
                print(f"[Node {self.port}] Successfully authenticated with bootstrap server")
            elif response_message == "FAILED":
                print(f"[Node {self.port}] Authentication failed with bootstrap server")
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

