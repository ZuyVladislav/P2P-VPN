# auth.py
# -*- coding: utf-8 -*-
"""Login + IP check (c генерацией временной RSA‑пары)."""
import socket
from typing import Dict, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa           # NEW
from cryptography.hazmat.primitives import serialization            # NEW

from config import USERS


class AuthError(Exception):
    ...


# --- helpers ---------------------------------------------------------------
def _b(v):
    """str → bytes (удобно, чтобы работать с PEM как bytes)."""
    return v.encode() if isinstance(v, str) else v


def _gen_temp_keys() -> Tuple[bytes, bytes]:                         # NEW
    """Сгенерировать приватный и публичный ключи RSA (PEM, bytes)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),          # без пароля
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem
# ---------------------------------------------------------------------------


def login(username: str, password: str, client_ip: str) -> Dict:
    user = USERS.get(username)
    if not user or user["password"] != password:
        raise AuthError("Неверные учётные данные")
    if user["ip"] != client_ip:
        raise AuthError(f"IP {client_ip} not allowed (expect {user['ip']})")

    # ─── ГЕНЕРИРУЕМ одноразовую пару для этой сессии ─────────────────────────
    temp_priv_pem, temp_pub_pem = _gen_temp_keys()                  # NEW

    return {
        "username": username,
        "ip": client_ip,
        # статичные ключи (если ещё нужны)
        "static_public_key": _b(user["static_public_key"]),
        "static_private_key": _b(user["static_private_key"]),
        # свежесгенерённые «в памяти» ключи
        "temp_public_key": temp_pub_pem,                             # NEW
        "temp_private_key": temp_priv_pem,                           # NEW
    }


def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()