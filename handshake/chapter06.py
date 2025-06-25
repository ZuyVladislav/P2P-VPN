# -*- coding: utf-8 -*-
"""
handshake.chapter06 – «глава 6»
Передача Child-SA(A-B) и инструкции I6   A → X₁ → X₂     (п. 6.1 – 6.9).

•  chan_a_x1  – имя DH-канала KD1(A-X1)   (по умолчанию 'A-X1')
•  chan_x1_x2 – имя DH-канала KD2(X1-X2)  (сейчас лишь для логов)

Исправлено:
* конверты к X₂ шифруются/расшифровываются функциями …_long;
* шаг 6.9 кладёт список RSA-чанков в inbox X₂ (их заберёт глава 8).
"""

from __future__ import annotations

import json
import logging
from typing import Dict, Any, List

from handshake.node import Node
from handshake.utils import (
    trace,
    rsa_encrypt_long,
    rsa_decrypt_long,
    sym_encrypt,
    sym_decrypt,
)

log = logging.getLogger("crypto.handshake")

_hexlist = lambda lst: [b.hex() for b in lst]            # List[bytes] → List[str]


# ─────────────────────────── глава 6 ──────────────────────────
def run(
    A: Node,
    X1: Node,
    X2: Node,
    B: Node,
    *,
    child_sa : Dict[str, Any] | None = None,
    address_B: str               = "B",
    chan_a_x1 : str              = "A-X1",     # NEW
    chan_x1_x2: str              = "X1-X2",    # NEW (пока только для trace)
) -> None:

    if child_sa is None:
        child_sa = {"ChildSA": "A-B"}

    log.info("ГЛАВА 6. %s → %s → %s : доставка Child-SA(A-B) + I6",
             A.name, X1.name, X2.name)

    # 6.1 — шифруем (RSA-long) пакет для B
    payload_61 = {"addr": address_B, "SA": child_sa, "I6": "set"}
    child_chunks = rsa_encrypt_long(B.pub(), json.dumps(payload_61).encode())

    trace("6.1", A.name, B.name, "RSA-long-enc",
          {"chunks": len(child_chunks)})

    # 6.2 — шифруем (RSA-long) обёртку для X₂
    env_dict  = {"inner_chunks": _hexlist(child_chunks), "I5": "relay"}
    env_chunks = rsa_encrypt_long(X2.pub(), json.dumps(env_dict).encode())
    trace("6.2", A.name, X2.name, "RSA-long-enc",
          {"chunks": len(env_chunks)})

    # 6.3 — KD1(A-X1) – симметричный слой
    outer_dict   = {"env_chunks_x2": _hexlist(env_chunks), "I4": "to_x2"}
    outer_cipher = sym_encrypt(A.dh_key(chan_a_x1),
                               json.dumps(outer_dict).encode())
    trace("6.3", A.name, X1.name, f"DH({chan_a_x1})-enc",
          {"bytes": len(outer_cipher)})

    # 6.4 — A → X₁
    X1.inbox.append(outer_cipher)
    trace("6.4", A.name, X1.name, "send", {"bytes": len(outer_cipher)})

    # 6.5 — X₁ принимает KD1-пакет
    pkt_65 = X1.inbox.pop(0)
    trace("6.5", X1.name, X1.name, "recv", {"bytes": len(pkt_65)})

    # 6.6 — снимаем KD1
    inner_json = sym_decrypt(X1.dh_key(chan_a_x1), pkt_65)
    inner_dict = json.loads(inner_json)
    env_hex    = inner_dict["env_chunks_x2"]          # List[str]
    trace("6.6", X1.name, X1.name, "DH-dec",
          {"chunks": len(env_hex)})

    # 6.7 — X₁ пересылает список чанков X₂
    env_chunks_x2 = [bytes.fromhex(h) for h in env_hex]
    X2.inbox.append(env_chunks_x2)
    trace("6.7", X1.name, X2.name, f"relay({chan_x1_x2})",
          {"chunks": len(env_chunks_x2)})

    # 6.8 — X₂ принимает список
    pkt_68: List[bytes] = X2.inbox.pop(0)
    trace("6.8", X2.name, X2.name, "RSA-recv", {"chunks": len(pkt_68)})

    # 6.9 — X₂ снимает свой RSA-слой, кладёт чанки для B
    env_plain = rsa_decrypt_long(X2.rsa_priv, pkt_68)
    env_dict2 = json.loads(env_plain)

    inner_chunks = [bytes.fromhex(h) for h in env_dict2["inner_chunks"]]
    X2.inbox.append(inner_chunks)                  # для главы 8

    trace("6.9", X2.name, X2.name, "RSA-long-dec",
          {"chunks": len(inner_chunks)})
    log.info("Глава 6 завершена")