# -*- coding: utf-8 -*-
"""
Diffie–Hellman helpers (без cryptography.backend).
- generate_parameters() → проверяем bit‑length p, g.
- safe defaults: key_size = 2048, generator = 2.
"""
from cryptography.hazmat.primitives.asymmetric import dh

__all__ = [
    "generate_parameters",
    "generate_private_key",
    "get_parameter_numbers",
    "get_public_value",
    "compute_shared_key",
]


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def generate_parameters(key_size: int = 2048) -> dh.DHParameters:
    """Generate safe‑prime DH parameters (p, g)."""
    if key_size < 1024:
        raise ValueError("DH key_size should be ≥ 1024 bits")
    return dh.generate_parameters(generator=2, key_size=key_size)


def generate_private_key(parameters: dh.DHParameters):
    """Generate DH private key from ready parameters."""
    return parameters.generate_private_key()


def get_parameter_numbers(parameters: dh.DHParameters) -> tuple[int, int]:
    nums = parameters.parameter_numbers()
    return nums.p, nums.g


def get_public_value(private_key) -> int:
    return private_key.public_key().public_numbers().y


def compute_shared_key(private_key, peer_y: int, p: int, g: int) -> bytes:
    peer_numbers = dh.DHPublicNumbers(peer_y, dh.DHParameterNumbers(p, g))
    peer_pub = peer_numbers.public_key()
    return private_key.exchange(peer_pub)