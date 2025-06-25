from __future__ import annotations

import json
import logging
from typing import Dict, Any, List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

from handshake.node import Node, _dh_peer_pub
from handshake.utils import (
    rsa_encrypt_long,
    rsa_decrypt_long,
    sha256,
    trace,
)

log = logging.getLogger("crypto.handshake")

# ────────────────────────────────────────────────────────────────

def run(A: Node, B: Node, *, dh_size: int | None = None) -> Dict[str, Any]:

    chan = "A-B"
    log.info("ГЛАВА 12. Узел-инициатор (А) обменивается с узлом-получателем (B) (напрямую) зашифрованные открытыми ключами RSA (OK(А), OK(B)) открытыми числами DH с целью вычисления секретного ключа DH")

    # 12.1 — A генерирует числа DH
    p, g, Ya = A.dh_generate(chan if dh_size is None else f"{chan}:{dh_size}")
    payload_A = {"p": p, "g": g, "Y": Ya}
    trace("12.1", A.name, A.name, "DH-gen", list(payload_A.keys()))
    log.debug("12.1  %s: p=%d … g=%d … Ya=%d", A.name, p, g, Ya)

    # 12.2 — A шифрует пакет для B (может быть >446 B)
    chunks_to_B: List[bytes] = rsa_encrypt_long(B.pub(), json.dumps(payload_A).encode())
    trace("12.2", A.name, B.name, "RSA-long-send", {"chunks": len(chunks_to_B)})

    # 12.3 — передаёт
    B.inbox.append(chunks_to_B)
    log.debug("12.3  B.inbox +1 (chunks=%d)", len(chunks_to_B))

    # 12.4 / 12.5 — B принимает и расшифровывает
    recv_25 = B.inbox.pop(0)
    plain_25 = rsa_decrypt_long(B.rsa_priv, recv_25)
    dhA = json.loads(plain_25)
    trace("12.5", B.name, B.name, "RSA-long-dec", list(dhA.keys()))

    # 12.6 — B вычисляет KD₄ и Yb
    params = dh.DHParameterNumbers(dhA["p"], dhA["g"]).parameters(default_backend())
    priv_B = params.generate_private_key()
    Yb = priv_B.public_key().public_numbers().y
    peer = _dh_peer_pub(dhA["p"], dhA["g"], dhA["Y"])
    B.dh_params[chan] = params
    B.dh_privs [chan] = priv_B
    B.dh_peerY[chan] = dhA["Y"]
    B.dh_shared[chan] = priv_B.exchange(peer)
    trace("12.6", B.name, B.name, "DH-compute", {"Yb": "generated"})
    log.debug("12.6  %s: KD4 len=%d B", B.name, len(B.dh_shared[chan]))

    # 12.7 — B шифрует свое Yb для A (тоже может быть >446 B)
    chunks_to_A: List[bytes] = rsa_encrypt_long(A.pub(), json.dumps({"Y": Yb}).encode())
    trace("12.7", B.name, A.name, "RSA-long-send", {"chunks": len(chunks_to_A)})

    # 12.8 — передача
    A.inbox.append(chunks_to_A)  # append в конец

    # 12.9 / 12.10 — A принимает, расшифровывает, завершает KD₄
    recv_A = A.inbox.pop()       # берем последний элемент
    plain_A = rsa_decrypt_long(A.rsa_priv, recv_A)
    Yb_recv = json.loads(plain_A)["Y"]
    trace("12.9", A.name, A.name, "RSA-long-dec", ["Y"])

    A.dh_set_peer(chan, Yb_recv)
    trace("12.10", A.name, B.name, "KD4-ready", {})
    log.debug("12.10 %s: KD4 len=%d B", A.name, len(A.dh_shared[chan]))

    return {
        "KD4(A)": sha256(A.dh_shared[chan]),
        "KD4(B)": sha256(B.dh_shared[chan]),
    }

    log.info("Глава 12 завершена")