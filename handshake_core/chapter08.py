# crypto/handshake/chapter8.py
from __future__ import annotations

import json
import logging
from typing import Dict, Any, List, Union

from handshake.node import Node
from handshake.utils import rsa_decrypt_long, trace

log = logging.getLogger("crypto.handshake")

# ───────────────────────────────────────────── chapter 8 ──
def run(X2: Node, B: Node) -> Dict[str, Any]:
    """
    Глава 8. Промежуточный узел X2 пересылает получателю B
    параметры Child-SA и I6, зашифрованные его публичным RSA-ключом.
    """

    log.info(
        "ГЛАВА 8. X2 → B: пересылка зашифрованных OK(B) параметров "
        "Child-SA (A-B) и инструкции I6"
    )

    # 8.1 — X₂ принимает список чанков (зашифр. ключом B) и пересылает B
    recv_obj: Union[List[bytes], bytes] = X2.inbox.pop(0)
    trace("8.1", X2.name, X2.name, "recv", {"type": type(recv_obj).__name__})

    # если вдруг прибыл одиночный bytes – обернём в список для унификации
    recv_chunks: List[bytes] = [recv_obj] if isinstance(recv_obj, bytes) else recv_obj

    B.inbox.append(recv_chunks)
    trace("8.1", X2.name, B.name, "RSA-relay", {"chunks": len(recv_chunks)})
    log.debug("8.1  relay_chunks=%d", len(recv_chunks))

    # 8.2 — B принимает список чанков
    pkt_chunks: List[bytes] = B.inbox.pop(0)
    trace("8.2", B.name, B.name, "recv-chunks", {"chunks": len(pkt_chunks)})
    log.debug("8.2  chunks_received=%d", len(pkt_chunks))

    # 8.3 — B расшифровывает длинным RSA и парсит JSON
    plain: bytes = rsa_decrypt_long(B.rsa_priv, pkt_chunks)
    payload: Dict[str, Any] = json.loads(plain)
    trace("8.3", B.name, B.name, "RSA-long-dec", list(payload.keys()))
    log.debug("8.3  payload_keys=%s", list(payload.keys()))

    # 8.4 — передаём расшифрованный payload самому B
    if hasattr(B, "handle_payload"):
        B.handle_payload(payload)
        trace("8.4", B.name, B.name, "handle_payload", {"stored": True})
        log.debug("8.4  Child-SA delivered to B.handle_payload()")
    else:
        log.warning(
            "Node %s lacks handle_payload(); Child-SA not stored", B.name
        )
        trace("8.4", B.name, B.name, "no-handle_payload", {})

    log.info("Глава 8 завершена")
    return payload