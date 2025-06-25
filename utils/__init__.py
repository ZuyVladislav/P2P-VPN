from pathlib import Path
from cryptography.hazmat.primitives import serialization

# Cache for loaded keys to avoid re-reading from disk
_key_cache = {}

# Determine the keys directory relative to this file (assuming project structure)
KEYS_DIR = Path(__file__).resolve().parent.parent / 'keys'

def load_private_key(user_name: str):
    """Load an RSA private key (.pem) for the given user name."""
    global _key_cache
    key_id = f"{user_name}:priv"
    if key_id in _key_cache:
        return _key_cache[key_id]
    # Determine file name: support both numeric and name-based keys
    if user_name.lower().startswith('user'):
        # e.g. user1 -> rsa_key1_private.pem
        num = user_name[4:]
        filename = f"rsa_key{num}_private.pem"
    else:
        # e.g. alice -> alice_priv.pem
        filename = f"{user_name.lower()}_priv.pem"
    key_path = KEYS_DIR / filename
    try:
        with open(key_path, 'rb') as key_file:
            # Load the PEM-formatted private key from file:contentReference[oaicite:15]{index=15}
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
            _key_cache[key_id] = private_key
            return private_key
    except FileNotFoundError:
        print(f"Private key file not found: {key_path}")
        return None

def load_public_key(user_name: str):
    """Load an RSA public key (or certificate) for the given user name."""
    global _key_cache
    key_id = f"{user_name}:pub"
    if key_id in _key_cache:
        return _key_cache[key_id]
    if user_name.lower().startswith('user'):
        # e.g. user1 -> rsa_key1_public.pem
        num = user_name[4:]
        filename = f"rsa_key{num}_public.pem"
    else:
        filename = f"{user_name.lower()}_pub.pem"
    key_path = KEYS_DIR / filename
    try:
        with open(key_path, 'rb') as key_file:
            # Load the PEM-formatted public key from file
            public_key = serialization.load_pem_public_key(
                key_file.read(),
            )
            _key_cache[key_id] = public_key
            return public_key
    except FileNotFoundError:
        print(f"Public key file not found: {key_path}")
        return None