# -*- coding: utf-8 -*-
"""
handshake.chapter02 – «глава 2»
A → X1 : отправка инструкции I1 поверх уже готового KD1(A-X1)

• chan_name – имя DH-канала (по-умолчанию "A-X1")
• text      – содержимое инструкции I1
"""

from __future__ import annotations

import json
import logging
from typing import Dict, Any

from handshake.node   import Node
from handshake.utils  import trace, sym_encrypt, sym_decrypt

log = logging.getLogger("crypto.handshake")


# ────────────────────────────────────────────────────────────
def run(
    A: Node,
    X1: Node,
    *,
    chan_name: str = "A-X1",
    text: str = "MOVE",
) -> Dict[str, Any]:
    """
    Отправляет I1 от A к X1 через уже существующий DH-канал KD1(chan_name).
    Возвращает расшифрованный словарь, который принял X1.
    """
    chan = chan_name
    log.info(
        "ГЛАВА 2. Узел-инициатор (A) → X1   передаёт инструкцию I1  "
        "[канал %s]", chan
    )

    # 2.1 A формирует полезную нагрузку
    payload: Dict[str, Any] = {"I1": text}
    log.debug("2.1  A сформировал I1-payload: %s", payload)

    # 2.2 A шифрует нагрузку ключом KD1(chan) и «отправляет» X1
    blob_22 = sym_encrypt(A.dh_key(chan), json.dumps(payload).encode())
    X1.inbox.append(blob_22)
    trace("2.2", A.name, X1.name, f"DH({chan})-send", {"bytes": len(blob_22)})
    log.debug("2.2  A → X1   DH-пакет длиной %d B отправлен", len(blob_22))

    # 2.3 X1 получает зашифрованный пакет
    blob_23 = X1.inbox.pop(0)
    trace("2.3", X1.name, X1.name, f"DH({chan})-recv", {"bytes": len(blob_23)})
    log.debug("2.3  X1 получил blob: %d B", len(blob_23))

    # 2.4 X1 расшифровывает пакет
    msg_24 = json.loads(sym_decrypt(X1.dh_key(chan), blob_23))
    trace("2.4", X1.name, X1.name, f"DH({chan})-dec", list(msg_24.keys()))
    log.debug("2.4  X1 расшифровал I1: %s", msg_24)

    log.info("Глава 2 завершена")
    return msg_24