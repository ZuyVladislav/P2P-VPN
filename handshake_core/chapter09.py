# -*- coding: utf-8 -*-
"""
handshake.chapter09 – «глава 9»
Обратная доставка Child-SA(B-A):  B → X₂ → X₁ → A
(подпункты 9.1–9.12 технического задания)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from handshake.node  import Node
from handshake.utils import (
    rsa_encrypt_long,
    rsa_decrypt_long,
    sym_encrypt,
    sym_decrypt,
    trace,
)

log = logging.getLogger("crypto.handshake")

# ─────────────── вспомогательный хелпер ────────────────
def _dh_key_fallback(node: Node, *candidates: str) -> bytes:
    """
    Вернуть первый доступный DH-ключ из списка `candidates`.
    Если ни один не найден – сгенерировать последнее RuntimeError.
    """
    last_exc: RuntimeError | None = None
    for name in candidates:
        try:
            return node.dh_key(name)
        except RuntimeError as exc:
            last_exc = exc
    assert last_exc is not None
    raise last_exc


# ──────────────────────────── глава 9 ────────────────────────────
def run(B: Node, X2: Node, X1: Node, A: Node) -> Dict[str, Any]:
    """
    Выполняет подпункты 9.1–9.12 и возвращает словарь Child-SA(B-A),
    который получил узел-инициатор A.
    """

    # «короткие» / «полные» имена DH-каналов
    chan_x2b_short  = "X2-B"
    chan_x2b_full   = f"{X2.name}-{B.name}"
    chan_x1x2_short = "X1-X2"
    chan_x1x2_full  = f"{X1.name}-{X2.name}"

    # 9.1 ─ B шифрует Child-SA(B-A) открытым RSA-ключом A
    child_sa_json = json.dumps({"SA": "B-A"}).encode()
    pkt_to_x2     = rsa_encrypt_long(A.pub(), child_sa_json)
    trace("9.1", B.name, A.name, "RSA-long-enc", {"chunks": len(pkt_to_x2)})
    log.debug("9.1  bytes_total=%d  chunk_count=%d",
              sum(len(c) for c in pkt_to_x2), len(pkt_to_x2))

    # 9.2 ─ B шифрует на KD3(X₂-B) + I7
    payload = json.dumps({
        "inner_chunks": [c.hex() for c in pkt_to_x2],
        "I7": "back",
    }).encode()
    blob_for_x2 = sym_encrypt(
        _dh_key_fallback(B, chan_x2b_short, chan_x2b_full),
        payload,
    )
    trace("9.2", B.name, X2.name, "DH(X2-B)-send", {"len": len(blob_for_x2)})

    # 9.3 ─ отправка X₂
    X2.inbox.append(blob_for_x2)
    trace("9.3", B.name, X2.name, "send", {"chunks": 1})

    # 9.4 ─ X₂ получает
    recv_x2 = X2.inbox.pop(0)
    trace("9.4", X2.name, X2.name, "recv", {"len": len(recv_x2)})

    # 9.5 ─ X₂ снимает KD3
    pkt_x2 = json.loads(
        sym_decrypt(
            _dh_key_fallback(B, chan_x2b_short, chan_x2b_full),
            recv_x2,
        )
    )
    trace("9.5", X2.name, B.name, "DH(X2-B)-dec", list(pkt_x2.keys()))

    # 9.6 ─ X₂ шифрует на KD2(X₁-X₂) + I8
    relay_pkt = json.dumps({
        "inner_chunks": pkt_x2["inner_chunks"],
        "I8": "relay_back",
    }).encode()
    blob_for_x1 = sym_encrypt(
        _dh_key_fallback(X2, chan_x1x2_short, chan_x1x2_full),
        relay_pkt,
    )
    trace("9.6", X2.name, X1.name, "DH(X1-X2)-send", {"len": len(blob_for_x1)})

    # 9.7 ─ отправка X₁
    X1.inbox.append(blob_for_x1)
    trace("9.7", X2.name, X1.name, "send", {"chunks": 1})

    # 9.8 ─ X₁ получает
    recv_x1 = X1.inbox.pop(0)
    trace("9.8", X1.name, X1.name, "recv", {"len": len(recv_x1)})

    # 9.9 ─ X₁ снимает KD2
    pkt_x1 = json.loads(
        sym_decrypt(
            _dh_key_fallback(X2, chan_x1x2_short, chan_x1x2_full),
            recv_x1,
        )
    )
    trace("9.9", X1.name, X2.name, "DH(X1-X2)-dec", list(pkt_x1.keys()))

    # 9.10 ─ X₁ ретранслирует чанки A
    X1.inbox.append(pkt_x1["inner_chunks"])
    trace("9.10", X1.name, A.name, "relay_chunks",
          {"chunks": len(pkt_x1["inner_chunks"])})

    # 9.11 ─ A получает список чанков
    recv_chunks_hex: List[str] = X1.inbox.pop(0)
    trace("9.11", A.name, A.name, "recv-chunks",
          {"chunk_count": len(recv_chunks_hex)})
    log.debug("9.11  chunk_count=%d", len(recv_chunks_hex))

    # 9.12 ─ A расшифровывает длинный RSA-конверт
    recv_chunks = [bytes.fromhex(h) for h in recv_chunks_hex]
    plain       = rsa_decrypt_long(A.rsa_priv, recv_chunks)
    child_sa    = json.loads(plain)
    trace("9.12", A.name, A.name, "RSA-long-dec", list(child_sa.keys()))
    log.debug("9.12  payload_keys=%s", list(child_sa.keys()))

    log.info("Глава 9 завершена")
    return child_sa