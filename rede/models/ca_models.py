class RegisterCertificateRequest:
    def __init__(self, id: str, public_key: int):
        self.id = id
        self.public_key = public_key

    def __repr__(self):
        return f"RegisterCertificateRequest(id={self.id}, public_key={self.public_key})"

class Certificate:
    def __init__(self, public_key: int, commitment: int, signature: int):
        self.public_key = public_key
        self.commitment = commitment
        self.signature = signature

    def __repr__(self):
        return f"Certificate(public_key={self.public_key}, s={self.signature}, r={self.commitment})"

    def to_bytes(self) -> bytes:
        """Serialize certificate for network transmission"""
        return f"{self.public_key},{self.commitment},{self.signature}".encode()

    @classmethod
    def from_bytes(cls, data):
        public_key = int.from_bytes(data[:256], 'big')
        r = int.from_bytes(data[256:512], 'big')
        s = int.from_bytes(data[512:], 'big')
        return cls(public_key, r, s)