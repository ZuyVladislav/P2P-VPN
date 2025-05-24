# -*- coding: utf-8 -*-
"""Temporary per‑session RSA keys with TTL & thread‑safety."""
from __future__ import annotations

import threading
import time
from collections import defaultdict

from cryptography.hazmat.primitives.asymmetric import rsa

_TTL_SEC = 60 * 60        # 1 h
_LOCK = threading.RLock()
_store: dict[str, tuple[float, rsa.RSAPrivateKey, rsa.RSAPublicKey]] = {}


def _purge_expired():
    now = time.time()
    for user, (ts, *_rest) in list(_store.items()):
        if now - ts > _TTL_SEC:
            _store.pop(user, None)


def generate_temp_keys(username: str, key_size: int = 2048):
    with _LOCK:
        _purge_expired()
        if username in _store:
            raise KeyError(f"Temp keys for {username!r} already exist")
        priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        _store[username] = (time.time(), priv, priv.public_key())


def _get(username: str):
    with _LOCK:
        try:
            return _store[username]
        except KeyError:
            raise KeyError(f"No temp keys for {username!r}")


def get_temp_private_key(username: str):
    return _get(username)[1]


def get_temp_public_key(username: str):
    return _get(username)[2]


def delete_temp_keys(username: str):
    with _LOCK:
        _store.pop(username, None)


def rotate_temp_keys(username: str, key_size: int = 2048):
    delete_temp_keys(username)
    generate_temp_keys(username, key_size)