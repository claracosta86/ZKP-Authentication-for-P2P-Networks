import socket
import threading

from rede.models.ca_models import Certificate
from rede.utils import validate


class BootStrapServer:
    def __init__(self, ip, port, ca_public_key, p, q, g):
        self.ip = ip
        self.port = port
        self.certificates = set()
        self.connected_nodes = {}  # {node_id: (ip, port)}
        self.ca_public_key = ca_public_key
        self.p = p
        self.q = q
        self.g = g

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.ip, self.port))
        server.listen()
        print(f"[BootStrapServer] Listening on {self.ip}:{self.port}")

        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle_peer, args=(conn, addr)).start()

    def validate_certificate(self, certificate: Certificate) -> bool:
        return validate.validate_certificate(certificate, self.p, self.q, self.g, self.ca_public_key)

    def handle_peer(self, conn, addr):
        try:
            request_type = conn.recv(4096).decode()

            if request_type == "AUTHENTICATE":
                self._handle_authentication(conn, addr)
            elif request_type.startswith("REQUEST_CERTIFICATES"):
                self._handle_certificate_request(conn, addr, request_type)
            else:
                conn.send(b"INVALID_REQUEST")
        except Exception as e:
            print(f"[BootStrapServer] Error handling peer: {e}")
        finally:
            conn.close()

    def _handle_authentication(self, conn, addr):
        data = conn.recv(4096)
        certificate = Certificate.from_bytes(data)

        if self.validate_certificate(certificate):
            conn.send(b"ACCEPTED")
            self.certificates.add(certificate)
            self.connected_nodes[certificate.public_key] = addr
            print(f"[BootStrapServer] New peer authenticated: {addr}")
        else:
            conn.send(b"REJECTED")

    def _handle_certificate_request(self, conn, addr, request_type):
        try:
            k = int(request_type.split(":")[1])
        except (IndexError, ValueError):
            conn.send(b"INVALID_REQUEST")
            return

        peer_public_key = next(
            (key for key, value in self.connected_nodes.items() if value == addr), None
        )
        if peer_public_key:
            certificates_to_send = list(self.certificates)[:k]
            for cert in certificates_to_send:
                conn.send(cert.to_bytes())
            print(f"[BootStrapServer] Sent {len(certificates_to_send)} certificates to {addr}")
        else:
            conn.send(b"UNAUTHENTICATED")
            print(f"[BootStrapServer] Peer {addr} is not authenticated")