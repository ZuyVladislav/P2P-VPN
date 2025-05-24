"""
config.py
Static VPN configuration: user credentials, allowed IP addresses and RSA keys.

All PEM files (rsa_keyX_public/private.pem) **must** be located in the same
directory as this module.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, TypedDict

# ————————————————————————————————————————————————————————————————
# Helpers & typing
# ————————————————————————————————————————————————————————————————

MODULE_DIR = Path(__file__).resolve().parent


def _read_pem(filename: str) -> bytes:
    """Return raw bytes from *filename* located next to this module."""
    return (MODULE_DIR / filename).read_bytes()


class UserEntry(TypedDict):
    password: str
    ip: str
    static_public_key: bytes
    static_private_key: bytes


# ————————————————————————————————————————————————————————————————
# Users
# ————————————————————————————————————————————————————————————————

USERS: Dict[str, UserEntry] = {
    "User1": {
        "password": "111111",
        "ip": "192.168.25.47",
        "static_public_key": _read_pem("rsa_key1_public.pem"),
        "static_private_key": _read_pem("rsa_key1_private.pem"),
    },
    "User2": {
        "password": "222222",
        "ip": "192.168.25.50",
        "static_public_key": _read_pem("rsa_key2_public.pem"),
        "static_private_key": _read_pem("rsa_key2_private.pem"),
    },
    "User3": {
        "password": "333333",
        "ip": "192.168.25.49",
        "static_public_key": _read_pem("rsa_key3_public.pem"),
        "static_private_key": _read_pem("rsa_key3_private.pem"),
    },
    "User4": {
        "password": "444444",
        "ip": "192.168.25.48",
        "static_public_key": _read_pem("rsa_key4_public.pem"),
        "static_private_key": _read_pem("rsa_key4_private.pem"),
    },
}

# ————————————————————————————————————————————————————————————————
# Network defaults
# ————————————————————————————————————————————————————————————————

DEFAULT_PORT: int = 5_000
BROADCAST_PORT: int = 5_001

__all__ = ["USERS", "DEFAULT_PORT", "BROADCAST_PORT"]