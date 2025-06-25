# -*- coding: utf-8 -*-
"""
handshake.chapter01 – «глава 1»
A ↔ X1 : IKE-фаза-1 + AUTH (KD1)

•   chan_name – имя DH-канала; по умолчанию "A-X1".
•   sa_label  – строка для поля SA (оставил прежнее значение).
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Dict, Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

from handshake.node   import Node, _dh_peer_pub
from handshake.utils  import (
    sha256, rsa_encrypt, rsa_decrypt,
    sym_encrypt, sym_decrypt, trace,
)

log = logging.getLogger("crypto.handshake")


# ────────────────────────────────────────────────────────────
def run(
    A: Node,
    X1: Node,
    *,
    chan_name: str = "A-X1",
    sa_label: str = "SA(A-X1)",
) -> Dict[str, Any]:
    """Фаза-1 IKEv2 A↔X1.  Возвращает финальный пакет 1.20."""
    chan = chan_name

    log.info(
        "ГЛАВА 1. Узел-инициатор (A) ↔ промежуточный (X1)  IKEv2-фаза-1"
        "   [канал %s]", chan
    )

    # 1.1 A генерирует DH-параметры
    p, g, Ya = A.dh_generate(chan)
    trace("1.1", A.name, A.name, "DH-gen", {"p": "…", "g": g, "Y": "…"})
    log.debug("1.1  |p| ≈ %d-бит, Ya готов", p.bit_length())

    # 1.2 A шлёт RSA-конверт X1
    pkt_12 = {
        "SA": sa_label,
        "nonce": secrets.token_hex(16),
        "DH": {"p": p, "g": g, "Y": Ya},
    }
    blob_12 = rsa_encrypt(X1.pub(), json.dumps(pkt_12).encode())
    X1.inbox.append(blob_12)          # «отправка в сеть»
    trace("1.2", A.name, X1.name, "RSA-send", list(pkt_12.keys()))

    # 1.3 сеть                            (только trace)
    trace("1.3", A.name, X1.name, "network", {"bytes": len(blob_12)})

    # 1.4 X1 принимает RSA-пакет
    blob_14 = X1.inbox.pop(0)
    trace("1.4", X1.name, X1.name, "RSA-recv", {"bytes": len(blob_14)})
    msg_14 = json.loads(rsa_decrypt(X1.rsa_priv, blob_14))
    trace("1.5", X1.name, X1.name, "RSA-dec", list(msg_14.keys()))

    # 1.6 X1 формирует KD1 и своё Y1
    DH_p, DH_g, Ya_recv = msg_14["DH"].values()
    params = dh.DHParameterNumbers(DH_p, DH_g).parameters(default_backend())
    priv1  = params.generate_private_key()
    Y1     = priv1.public_key().public_numbers().y
    X1.dh_params[chan] = params
    X1.dh_privs [chan] = priv1
    X1.dh_peerY[chan]  = Ya_recv
    X1.dh_shared[chan] = priv1.exchange(_dh_peer_pub(DH_p, DH_g, Ya_recv))
    trace("1.6", X1.name, X1.name, f"DH({chan})", {"Y1": "…"})

    # 1.7 X1 → A   RSA-ответ
    pkt_17 = {"SA": "sel", "nonce": secrets.token_hex(16), "DH": {"Y": Y1}}
    blob_17 = rsa_encrypt(A.pub(), json.dumps(pkt_17).encode())
    A.inbox.append(blob_17)
    trace("1.7", X1.name, A.name, "RSA-send", list(pkt_17.keys()))

    # 1.8 сеть
    trace("1.8", X1.name, A.name, "network", {"bytes": len(blob_17)})

    # 1.9 A принимает RSA-ответ
    blob_19 = A.inbox.pop(0)
    trace("1.9", A.name, A.name, "RSA-recv", {"bytes": len(blob_19)})
    Y1_recv = json.loads(rsa_decrypt(A.rsa_priv, blob_19))["DH"]["Y"]
    trace("1.10", A.name, A.name, "RSA-dec", ["Y"])

    # 1.11 A завершает KD1
    A.dh_set_peer(chan, Y1_recv)
    trace("1.11", A.name, A.name, f"KD1({chan})", {"status": "ready"})

    # 1.12–1.14 A → X1  Hash(A)+II
    hash_A = sha256(b"A")
    blob_213 = sym_encrypt(A.dh_key(chan), json.dumps(
        {"Hash": hash_A, "II": f"II({A.name}-{X1.name})"}).encode())
    X1.inbox.append(blob_213)
    trace("1.13", A.name, X1.name, f"DH({chan})-send", ["Hash", "II"])
    trace("1.14", A.name, X1.name, f"network", {"bytes": len(blob_213)})

    # 1.15 X1 принимает Hash(A)
    pkt_15 = json.loads(sym_decrypt(X1.dh_key(chan), X1.inbox.pop(0)))
    trace("1.15", X1.name, X1.name, f"DH({chan})-dec", list(pkt_15.keys()))

    # 1.17–1.19 X1 → A  Hash(X1)+II
    hash_X1 = sha256(b"X1")
    blob_218 = sym_encrypt(X1.dh_key(chan), json.dumps(
        {"Hash": hash_X1, "II": f"II({X1.name}-{A.name})"}).encode())
    A.inbox.append(blob_218)
    trace("1.18", X1.name, A.name, f"DH({chan})-send", ["Hash", "II"])
    trace("1.19", X1.name, A.name, "network", {"bytes": len(blob_218)})

    # 1.20 A принимает Hash(X1)
    pkt_20 = json.loads(sym_decrypt(A.dh_key(chan), A.inbox.pop(0)))
    trace("1.20", A.name, A.name, f"DH({chan})-dec", list(pkt_20.keys()))

    log.info("Глава 1 завершена  (канал %s)", chan)
    return pkt_20