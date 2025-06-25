# -*- coding: utf-8 -*-
"""
handshake.chapter10 – «глава 10»
Передача AI(A-B) по цепочке A → X₁ → X₂ → B (пункты 10.1–10.12).
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
    """Пробует несколько имён канала подряд, возвращает первый найденный."""
    last_exc: RuntimeError | None = None
    for name in candidates:
        try:
            return node.dh_key(name)
        except RuntimeError as exc:
            last_exc = exc
    assert last_exc is not None
    raise last_exc


# ─────────────────────────── глава 10 ────────────────────────────
def run(
    A: Node,
    X1: Node,
    X2: Node,
    B: Node,
    *,
    ai_payload: Dict[str, Any] | None = None,
) -> Dict[str, Any]:

    if ai_payload is None:
        ai_payload = {"AI(A-B)": "data"}

    # возможные имена DH-каналов
    chan_ax1_short  = "A-X1"
    chan_ax1_full   = f"{A.name}-{X1.name}"
    chan_x1x2_short = "X1-X2"
    chan_x1x2_full  = f"{X1.name}-{X2.name}"

    # 10.1 ─ A шифрует AI(A-B) открытым RSA-ключом B
    inner_plain   = json.dumps(ai_payload).encode()
    inner_chunks  = rsa_encrypt_long(B.pub(), inner_plain)
    trace("10.1", A.name, B.name, "RSA-long-enc", {"chunks": len(inner_chunks)})
    log.debug("10.1  inner_cipher=%d B", sum(len(c) for c in inner_chunks))

    # 10.2 ─ A убирает в DH-конверт KD1(A-X1) + I11
    env_a_plain   = json.dumps({
        "inner_chunks": [c.hex() for c in inner_chunks],
        "I11": "toX1",
    }).encode()
    outer_cipher  = sym_encrypt(
        _dh_key_fallback(A, chan_ax1_short, chan_ax1_full),
        env_a_plain,
    )
    trace("10.2", A.name, X1.name, "DH(A-X1)-send", {"len": len(outer_cipher)})

    # 10.3 ─ A → X₁
    X1.inbox.append(outer_cipher)
    trace("10.3", A.name, X1.name, "send", {"chunks": 1})

    # 10.4 ─ X₁ получает
    recv_x1 = X1.inbox.pop(0)
    trace("10.4", X1.name, X1.name, "recv", {"len": len(recv_x1)})

    # 10.5 ─ X₁ снимает KD1
    env_a_dec = sym_decrypt(
        _dh_key_fallback(A, chan_ax1_short, chan_ax1_full),
        recv_x1,
    )
    pkt_x1 = json.loads(env_a_dec)
    trace("10.5", X1.name, A.name, "DH(A-X1)-dec", list(pkt_x1.keys()))

    # 10.6 ─ X₁ зашифровывает пакет для X₂ на KD2(X₁-X₂) + I12
    env_x1_plain = json.dumps({
        "inner_chunks": pkt_x1["inner_chunks"],
        "I12": "toX2",
    }).encode()
    env_x1_cipher = sym_encrypt(
        _dh_key_fallback(X1, chan_x1x2_short, chan_x1x2_full),
        env_x1_plain,
    )
    trace("10.6", X1.name, X2.name, "DH(X1-X2)-send", {"len": len(env_x1_cipher)})

    # 10.7 ─ X₁ → X₂
    X2.inbox.append(env_x1_cipher)
    trace("10.7", X1.name, X2.name, "send", {"chunks": 1})

    # 10.8 ─ X₂ получает
    recv_x2 = X2.inbox.pop(0)
    trace("10.8", X2.name, X2.name, "recv", {"len": len(recv_x2)})

    # 10.9 ─ X₂ снимает KD2
    env_plain_dec = sym_decrypt(
        _dh_key_fallback(X1, chan_x1x2_short, chan_x1x2_full),
        recv_x2,
    )
    pkt_x2 = json.loads(env_plain_dec)
    trace("10.9", X2.name, X2.name, "DH(X1-X2)-dec", list(pkt_x2.keys()))

    # 10.10 ─ X₂ пересылает список RSA-чанков B
    inner_chunks_hex: List[str] = pkt_x2["inner_chunks"]
    B.inbox.append(inner_chunks_hex)
    trace("10.10", X2.name, B.name, "relay-chunks",
          {"chunk_count": len(inner_chunks_hex)})

    # 10.11 ─ B получает
    recv_chunks_hex: List[str] = B.inbox.pop(0)
    trace("10.11", B.name, B.name, "recv-chunks",
          {"chunk_count": len(recv_chunks_hex)})

    # 10.12 ─ B расшифровывает AI(A-B)
    recv_chunks = [bytes.fromhex(h) for h in recv_chunks_hex]
    ai_dec      = json.loads(rsa_decrypt_long(B.rsa_priv, recv_chunks))
    trace("10.12", B.name, B.name, "RSA-long-dec", list(ai_dec.keys()))

    log.info("Глава 10 завершена")
    return ai_dec