import sympy
import random

class PrimeGenerator:
    def __init__(self, bits=256):
        self.bits = bits

    @staticmethod
    def generate_safe_prime(bits=256):
        while True:
            q = sympy.randprime(2**(bits-2), 2**(bits-1))
            p = 2 * q + 1
            if sympy.isprime(p):
                return p, q
    
    @staticmethod
    def find_generator(p, q):
        for g in range(2, p):
            if pow(g, q, p) != 1:
                return g
        raise Exception("No generator found.")

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
