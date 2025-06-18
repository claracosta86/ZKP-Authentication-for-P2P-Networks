import sympy
import random

p_hex = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381
FFFFFFFFFFFFFFFF
"""

p = int(p_hex.replace('\n', '').replace(' ', ''), 16)
g = 2
q = (p - 1) // 2


def get_encrypting_values():
    return p, q, g

class SchnorrZKP:
    def __init__(self, p, q, g):
        self.p = p
        self.q = q
        self.g = g
        self.secret = random.randint(1, q-1)
        self.public = pow(g, self.secret, p)

    def create_commitment(self):
        self.r = random.randint(1, self.q-1)
        self.R = pow(self.g, self.r, self.p)
        return self.R

    def compute_response(self, challenge):
        s = (self.r + challenge * self.secret) % self.q
        return s

    def verify(self, R, public, challenge, s):
        left = pow(self.g, s, self.p)
        right = (R * pow(public, challenge, self.p)) % self.p
        return left == right
