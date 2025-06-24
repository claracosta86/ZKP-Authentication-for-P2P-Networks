class AuthenticationRequest:

    def __init__(self, public_key, commitment, signature):
        self.public_key = public_key
        self.commitment = commitment
        self.signature = signature


class AuthenticationCommitmentRequest:

    def __init__(self, commitment):
        self.commitment = commitment


class AuthenticationVerificationRequest:

    def __init__(self, r: int, V: list, certificates: list):
        self.r = r
        self.V = V
        self.certificates = certificates