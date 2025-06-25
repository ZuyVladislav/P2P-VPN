# -*- coding: utf-8 -*-
"""
handshake.chapter04 – «глава 4»
X1 → X2 : I2   ⟶   OK1(X2) + I3   (работает поверх KD2)

Parameters
----------
chan_name : str, optional
    Идентификатор DH-канала KD2(X1-X2).
    Если не передан – будет создан автоматически «X1-X2».
i2_text / i3_text : str
    Содержимое инструкций I2 и I3.
"""

from __future__ import annotations

import logging
from typing import Dict, Any

from cryptography.hazmat.primitives import serialization

from handshake.node  import Node
from handshake.utils import trace

log = logging.getLogger("crypto.handshake")


# ────────────────────────────────────────────────────────────
def run(
    X1: Node,
    X2: Node,
    *,
    chan_name: str | None = None,
    i2_text: str = "GET_OK",
    i3_text: str = "NEXT",
) -> Dict[str, Any]:
    """Возвращает словарь ``{"OK1(X2)": <PEM-str>, "I3": <text>}``."""
    chan = chan_name or f"{X1.name}-{X2.name}"

    log.info(
        "ГЛАВА 4. %s → %s  передаёт I2 и получает OK1(X2)  [канал %s]",
        X1.name, X2.name, chan,
    )

    # ───────────── 4.1  X1 → X2 : I2 (KD2-шифр) ────────────────
    X1.send_sym(chan, X2, {"I2": i2_text}, step="4.1")
    trace("4.2", X1.name, X2.name, f"DH({chan})-send", ["I2"])

    # ───────────── 4.3  X2 принимает I2 ────────────────────────
    pkt_43 = X2.recv_sym(chan)
    trace("4.3", X2.name, X2.name, f"DH({chan})-recv", pkt_43)

    # ───────────── 4.4  X2 формирует OK1(X2)+I3 ───────────────
    ok1_pem = X2.pub().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    answer_45: Dict[str, Any] = {"OK1(X2)": ok1_pem, "I3": i3_text}
    X2.send_sym(chan, X1, answer_45, step="4.5")
    trace("4.6", X2.name, X1.name, f"DH({chan})-send", ["OK1(X2)", "I3"])

    # ───────────── 4.7  X1 принимает ответ ─────────────────────
    pkt_47 = X1.recv_sym(chan)
    trace("4.7", X1.name, X1.name, f"DH({chan})-recv", list(pkt_47.keys()))
    trace("4.8", X1.name, X1.name, f"DH({chan})-dec", {"I3": pkt_47.get("I3")})

    log.info("Глава 4 завершена  (канал %s)", chan)
    return pkt_47