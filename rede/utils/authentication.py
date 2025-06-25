import random
import secrets

from rede.node.node import Node


def prepare_commitment(node: Node) -> dict:
    """Prepares the commitment phase data."""
    chosen_certificates = random.sample(node.certificates, node.certificates_n - 1)
    s = secrets.randbelow(node.q)
    V = [secrets.randbelow(node.q) for _ in range(node.certificates_n - 1)]
    commitment = node.get_authentication_commitment_request(s, V, chosen_certificates)
    return {"s": s, "V": V, "certificates": chosen_certificates, "commitment": commitment}

def prepare_verification(node: Node, commitment_data: dict, challenge: int):
    """Prepares verification data based on commitment and challenge."""
    return node.get_authentication_verification_request(
        commitment_data["s"],
        challenge,
        commitment_data["V"],
        commitment_data["certificates"]
    )
