# -*- coding: utf-8 -*-
"""
handshake.chapter07 – «глава 7»
X2 ↔ B : IKE-фаза-1 + AUTH  (KD3)

Параметры
---------
chan_name : str = "X2-B"
    Имя DH-канала.  Multistart передаёт уникальные значения
    (напр. "X2_L2_1-B"), чтобы ключи разных веток не перезаписывались.
sa_proposal : dict | None
    Предложение SA; если None, формируется {"SA": f"SA({chan_name})"}.
"""

from __future__ import annotations

import json
import logging
import secrets
from typing import Any, Dict, List, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

from handshake.node  import Node, _dh_peer_pub
from handshake.utils import (
    rsa_encrypt, rsa_encrypt_long,
    rsa_decrypt, rsa_decrypt_long,
    sym_encrypt, sym_decrypt,
    sha256, trace,
)

log = logging.getLogger("crypto.handshake")


# ───────────────────────────────────────────── chapter 7 ──
def run(
    X2: Node,
    B: Node,
    *,
    chan_name: str = "X2-B",
    sa_proposal: Dict[str, Any] | None = None,
) -> None:
    """Подпункты 7.1 – 7.21.  На выходе сформирован KD3(chan_name)."""

    chan = chan_name
    if sa_proposal is None:
        sa_proposal = {"SA": f"SA({chan})"}

    log.info(
        "ГЛАВА 7. X2 ↔ B  IKEv2-фаза-1   [канал %s]", chan
    )

    # 7.1 — X2 генерирует DH-параметры
    p, g, Y2 = X2.dh_generate(chan)
    trace("7.1", X2.name, X2.name, "DH-gen", {"bits": p.bit_length()})

    # 7.2 — RSA-конверт для B  (может быть >446 B)
    payload_72 = {
        **sa_proposal,
        "nonce": secrets.token_hex(16),
        "DH": {"p": p, "g": g, "Y": Y2},
    }
    chunks_72: List[bytes] = rsa_encrypt_long(
        B.pub(), json.dumps(payload_72).encode()
    )
    trace("7.2", X2.name, B.name, "RSA-long-enc",
          {"chunks": len(chunks_72)})

    # 7.3 — X2 → B
    B.inbox.append(chunks_72)
    trace("7.3", X2.name, B.name, "RSA-send",
          {"chunks": len(chunks_72)})

    # 7.4 – 7.5 — B принимает и расшифровывает
    recv_75: Union[bytes, List[bytes]] = B.inbox.pop(0)
    trace("7.4", B.name, B.name, "RSA-recv",
          {"type": type(recv_75).__name__})
    plain_75 = (
        rsa_decrypt_long(B.rsa_priv, recv_75)
        if isinstance(recv_75, list)
        else rsa_decrypt(B.rsa_priv, recv_75)
    )
    msg_75 = json.loads(plain_75)
    trace("7.5", B.name, B.name, "RSA-dec", list(msg_75.keys()))

    # 7.6 — B формирует KD3
    DH_p, DH_g, Y2_recv = msg_75["DH"].values()
    prm_B  = dh.DHParameterNumbers(DH_p, DH_g).parameters(default_backend())
    priv_B = prm_B.generate_private_key()
    YB     = priv_B.public_key().public_numbers().y
    peer   = _dh_peer_pub(DH_p, DH_g, Y2_recv)
    B.dh_params[chan]  = prm_B
    B.dh_privs [chan]  = priv_B
    B.dh_peerY[chan]   = Y2_recv
    B.dh_shared[chan]  = priv_B.exchange(peer)
    trace("7.6", B.name, B.name, f"DH({chan})", {"YB": "…"})

    # 7.7 – 7.8 — B → X2  (RSA-ответ, короткий)
    payload_78 = {
        "SA": "sel",
        "nonce": secrets.token_hex(16),
        "DH": {"Y": YB},
    }
    blob_78 = rsa_encrypt(X2.pub(), json.dumps(payload_78).encode())
    X2.inbox.append(blob_78)
    trace("7.8", B.name, X2.name, "RSA-send",
          {"bytes": len(blob_78)})

    # 7.9 – 7.10 — X2 принимает RSA-ответ
    blob_710 = X2.inbox.pop()
    trace("7.9", X2.name, X2.name, "RSA-recv",
          {"type": type(blob_710).__name__})
    plain_710 = (
        rsa_decrypt_long(X2.rsa_priv, blob_710)
        if isinstance(blob_710, list)
        else rsa_decrypt(X2.rsa_priv, blob_710)
    )
    msg_710 = json.loads(plain_710)
    trace("7.10", X2.name, X2.name, "RSA-dec", list(msg_710.keys()))

    # 7.11 — X2 завершает KD3
    X2.dh_set_peer(chan, msg_710["DH"]["Y"])
    trace("7.11", X2.name, X2.name, f"KD3({chan})", {"status": "ready"})

    # 7.12 – 7.14 — X2 → B  (AUTH-хеш)
    auth_713 = {"Hash": sha256(b"X2"), "II": f"II({X2.name}-{B.name})"}
    blob_713 = sym_encrypt(X2.dh_key(chan),
                           json.dumps(auth_713).encode())
    B.inbox.append(blob_713)
    trace("7.13", X2.name, B.name, f"DH({chan})-send",
          {"bytes": len(blob_713)})

    blob_716 = B.inbox.pop(0)
    trace("7.14", B.name, B.name, f"DH({chan})-recv",
          {"bytes": len(blob_716)})
    msg_716 = json.loads(sym_decrypt(B.dh_key(chan), blob_716))
    trace("7.16", B.name, B.name, f"DH({chan})-dec",
          list(msg_716.keys()))

    # 7.17 – 7.19 — B → X2  (AUTH-ответ)
    auth_718 = {"Hash": sha256(b"B"), "II": f"II({B.name}-{X2.name})"}
    blob_718 = sym_encrypt(B.dh_key(chan),
                           json.dumps(auth_718).encode())
    X2.inbox.append(blob_718)
    trace("7.18", B.name, X2.name, f"DH({chan})-send",
          {"bytes": len(blob_718)})

    blob_721 = X2.inbox.pop()
    trace("7.19", X2.name, X2.name, f"DH({chan})-recv",
          {"bytes": len(blob_721)})
    msg_721 = json.loads(sym_decrypt(X2.dh_key(chan), blob_721))
    trace("7.21", X2.name, X2.name, f"DH({chan})-dec",
          list(msg_721.keys()))

    log.info("Глава 7 завершена  (канал %s)", chan)