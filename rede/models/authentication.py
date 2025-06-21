class AuthenticationRequest:

    def __init__(self, public_key, commitment, signature):
        self.public_key = public_key
        self.commitment = commitment
        self.signature = signature