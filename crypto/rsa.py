# -*- coding: utf-8 -*-
"""RSA helpers (PKCS#8 / OAEP)"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

__all__ = [
    "generate_key_pair",
    "serialize_private_key",
    "serialize_public_key",
    "load_private_key",
    "load_public_key",
    "encrypt",
    "decrypt",
]

KEY_SIZE = 2048


def generate_key_pair(key_size: int = KEY_SIZE):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return priv, priv.public_key()


def serialize_private_key(priv, password: bytes | None = None) -> bytes:
    algo = (serialization.BestAvailableEncryption(password)
            if password else serialization.NoEncryption())
    return priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        algo,
    )


def serialize_public_key(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem: bytes, password: bytes | None = None):
    return serialization.load_pem_private_key(pem, password=password)


def load_public_key(pem: bytes):
    return serialization.load_pem_public_key(pem)


def encrypt(pub, data: bytes) -> bytes:
    return pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt(priv, data: bytes) -> bytes:
    return priv.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
