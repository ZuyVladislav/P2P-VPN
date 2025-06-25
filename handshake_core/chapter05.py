# -*- coding: utf-8 -*-
"""
handshake.chapter05 – «глава 5»
X1 → A : пересылка OK1(X2) + I4  (по KD1(A-X1))
"""

from __future__ import annotations

import logging, json
from typing import Dict, Any

from handshake.node  import Node
from handshake.utils import trace

log = logging.getLogger("crypto.handshake")


# ────────────────────────────────────────────────────────────
def run(
    X1: Node,
    A:  Node,
    *,
    ok1_pem: str,
    i4_text: str = "OK_RECEIVED",
    chan_name: str = "A-X1",          # ← новый параметр!
) -> Dict[str, Any]:
    """Отправляет OK1(X2) инициатору A по KD1(chan_name)."""
    chan = chan_name
    log.info(
        "ГЛАВА 5. %s → %s  отправляет открытый ключ X2 [канал %s]",
        X1.name, A.name, chan
    )

    # 5.1  формируем пакет
    payload = {"OK1(X2)": ok1_pem, "I4": i4_text}
    X1.send_sym(chan, A, payload, step="5.1")      # KD1-шифр
    trace("5.2", X1.name, A.name, f"DH({chan})-send", list(payload.keys()))

    # 5.2
    msg = A.recv_sym(chan)
    trace("5.3", A.name, A.name, f"DH({chan})-recv", list(msg.keys()))
    log.info("Глава 5 завершена  (канал %s)", chan)
    return msg