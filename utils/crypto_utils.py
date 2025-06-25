# utils/crypto_utils.py
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def load_private_key(path: Path):
    """
    Загружает приватный RSA-ключ из PEM-файла.
    """
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def load_public_key(path: Path):
    """
    Загружает публичный RSA-ключ из PEM-файла.
    """
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )