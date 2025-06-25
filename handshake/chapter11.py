# -*- coding: utf-8 -*-
"""
handshake.chapter11 – «глава 11»
Ответная передача AI(B-A) по цепочке B → X₂ → X₁ → A (пункты 11.1–11.12).
"""

from __future__ import annotations

import json
import logging
from typing import Dict, Any, List

from handshake.node  import Node
from handshake.utils import (
    rsa_encrypt_long,
    rsa_decrypt_long,
    sym_encrypt,
    sym_decrypt,
    trace,
)

log = logging.getLogger("crypto.handshake")

# ─────────── вспомогательный хелпер ───────────
def _dh_key_fallback(node: Node, *candidates: str) -> bytes:
    last_exc: RuntimeError | None = None
    for name in candidates:
        try:
            return node.dh_key(name)
        except RuntimeError as exc:
            last_exc = exc
    assert last_exc is not None
    raise last_exc


# ─────────────────────────── глава 11 ────────────────────────────
def run(
    A: Node,
    X1: Node,
    X2: Node,
    B: Node,
    *,
    ai_payload: Dict[str, Any] | None = None,
) -> Dict[str, Any]:

    if ai_payload is None:
        ai_payload = {"AI(B-A)": "data"}

    # возможные имена DH-каналов
    chan_x2b_short  = "X2-B"
    chan_x2b_full   = f"{X2.name}-{B.name}"
    chan_x1x2_short = "X1-X2"
    chan_x1x2_full  = f"{X1.name}-{X2.name}"

    # 11.1 ─ B шифрует AI(B-A) открытым RSA-ключом A
    inner_plain   = json.dumps(ai_payload).encode()
    inner_chunks  = rsa_encrypt_long(A.pub(), inner_plain)
    trace("11.1", B.name, A.name, "RSA-long-enc", {"chunks": len(inner_chunks)})
    log.debug("11.1  len(inner_cipher)=%d", sum(len(c) for c in inner_chunks))

    # 11.2 ─ B кладёт всё в DH-конверт KD3(X₂-B) + I11
    env_b_plain   = json.dumps({
        "inner_chunks": [c.hex() for c in inner_chunks],
        "I11": "toX2",
    }).encode()
    env_b_cipher  = sym_encrypt(
        _dh_key_fallback(B, chan_x2b_short, chan_x2b_full),
        env_b_plain,
    )
    trace("11.2", B.name, X2.name, "DH(X2-B)-send", {"len": len(env_b_cipher)})

    # 11.3 ─ B → X₂
    X2.inbox.append(env_b_cipher)
    trace("11.3", B.name, X2.name, "send", {"chunks": 1})

    # 11.4 ─ X₂ получает
    recv_x2 = X2.inbox.pop(0)
    trace("11.4", X2.name, X2.name, "recv", {"len": len(recv_x2)})

    # 11.5 ─ X₂ снимает KD3
    env_x2_plain = sym_decrypt(
        _dh_key_fallback(B, chan_x2b_short, chan_x2b_full),
        recv_x2,
    )
    pkt_x2  = json.loads(env_x2_plain)
    trace("11.5", X2.name, B.name, "DH(X2-B)-dec", list(pkt_x2.keys()))

    # 11.6 ─ X₂ зашифровывает пакет на KD2(X₁-X₂) + I12
    env_x2_plain2 = json.dumps({
        "inner_chunks": pkt_x2["inner_chunks"],
        "I12": "toX1",
    }).encode()
    env_x2_cipher2 = sym_encrypt(
        _dh_key_fallback(X2, chan_x1x2_short, chan_x1x2_full),
        env_x2_plain2,
    )
    trace("11.6", X2.name, X1.name, "DH(X1-X2)-send", {"len": len(env_x2_cipher2)})

    # 11.7 ─ X₂ → X₁
    X1.inbox.append(env_x2_cipher2)
    trace("11.7", X2.name, X1.name, "send", {"chunks": 1})

    # 11.8 ─ X₁ получает
    recv_x1 = X1.inbox.pop(0)
    trace("11.8", X1.name, X1.name, "recv", {"len": len(recv_x1)})

    # 11.9 ─ X₁ снимает KD2
    env_x1_plain = sym_decrypt(
        _dh_key_fallback(X2, chan_x1x2_short, chan_x1x2_full),
        recv_x1,
    )
    pkt_x1 = json.loads(env_x1_plain)
    trace("11.9", X1.name, X2.name, "DH(X1-X2)-dec", list(pkt_x1.keys()))

    # 11.10 ─ X₁ пересылает список RSA-чанков A
    inner_chunks_hex: List[str] = pkt_x1["inner_chunks"]
    A.inbox.append(inner_chunks_hex)
    trace("11.10", X1.name, A.name, "relay-chunks",
          {"chunk_count": len(inner_chunks_hex)})

    # 11.11 ─ A получает
    recv_chunks_hex: List[str] = A.inbox.pop(0)
    trace("11.11", A.name, A.name, "recv-chunks",
          {"chunk_count": len(recv_chunks_hex)})

    # 11.12 ─ A расшифровывает AI(B-A)
    recv_chunks = [bytes.fromhex(h) for h in recv_chunks_hex]
    ai_dec      = json.loads(rsa_decrypt_long(A.rsa_priv, recv_chunks))
    trace("11.12", A.name, A.name, "RSA-long-dec", list(ai_dec.keys()))

    log.info("Глава 11 завершена")
    return ai_dec