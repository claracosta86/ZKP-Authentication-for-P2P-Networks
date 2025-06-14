class RegisterCertificateRequest:
    def __init__(self, id: str, public_key: int):
        self.id = id
        self.public_key = public_key

    def __repr__(self):
        return f"RegisterCertificateRequest(id={self.id}, public_key={self.public_key})"

class Certificate:
    def __init__(self, public_key: int, r: int, s: int):
        self.public_key = public_key
        self.r = r
        self.s = s

    def __repr__(self):
        return f"Certificate(public_key={self.public_key}, s={self.s}, r={self.r})"