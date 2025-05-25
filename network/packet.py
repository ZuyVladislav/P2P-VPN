# -*- coding: utf-8 -*-
"""
network/packet.py
─────────────────
• типы «прикладных» пакетов верхнего уровня (CON­NECT_*, CHAT_MESSAGE);
• вспомогательный класс MultiStartConnector – реализация многостартовой
  маршрутизации начального CONNECT_REQUEST.
"""
from __future__ import annotations

import json
import logging
import random
import uuid
from copy import deepcopy
from typing import Dict, List, Set

from network.transport import send_packet

# ────────────────────────────────────────────────────────────────────────────
#  Публичные константы, которыми обменивается GUI/transport
# ────────────────────────────────────────────────────────────────────────────
CONNECT_REQ: str = "CONNECT_REQUEST"      # A → B   (username_from)
CONNECT_ACCEPT: str = "CONNECT_ACCEPT"    # B → A
CONNECT_DECLINE: str = "CONNECT_DECLINE"  # B → A
CHAT_MESSAGE: str = "CHAT_MESSAGE"        # A ↔ B   (text)

__all__ = [
    # публичные константы
    "CONNECT_REQ",
    "CONNECT_ACCEPT",
    "CONNECT_DECLINE",
    "CHAT_MESSAGE",
    # вспомогательный класс
    "MultiStartConnector",
]

log = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
#  Маршрутизация «многостартового» CONNECT_REQUEST
# ────────────────────────────────────────────────────────────────────────────
class MultiStartConnector:
    """
    Простейший вариант «многостартового» отправления CONNECT_REQUEST.
    На каждом этапе fan-out ограничивается FANOUT[stage].
    """

    FANOUT = {1: 3, 2: 3, 3: 2}  # сколько копий рассылать на каждом этапе

    def __init__(self, me: str, peers: Dict[str, str]):
        self.me = me                         # моё username
        self.peers = peers                   # {username: ip}
        self.target: str | None = None       # кого ищем
        self.received: List[dict] = []       # финальные пакеты, пришедшие «мне»
        self._seen: Set[str] = set()         # id уже обработанных пакетов

    # ---------------------------------------------------------------- public
    def start(self, target: str, security: dict | None = None) -> None:
        """Запустить рассылку CONNECT_REQUEST."""
        self.target = target
        first = self._make_packet(target, stage=1, security=security)
        self._fanout(first, self.FANOUT[1], exclude={self.me})

    def on_receive(self, raw: bytes, _addr: str) -> None:
        """Обработать входящий UDP-пакет (вызывается transport-слушателем)."""
        try:
            pkt = json.loads(raw.decode())
        except Exception:
            return

        pid: str | None = pkt.get("id")
        if not pid or pid in self._seen:
            return
        self._seen.add(pid)

        if pkt.get("target") != self.target:
            return

        stage = int(pkt.get("stage", 0))
        log.debug("pkt %s stage %s route=%s", pid[:8], stage, pkt["route"])

        if stage < 3:
            next_stage = stage + 1
            fanout = self.FANOUT.get(next_stage, 0)
            exclude = {self.me}
            if next_stage == 3:
                exclude.add(self.target)
            self._fanout(pkt, fanout, exclude, stage_override=next_stage)
        else:
            # stage ≥ 3 → пакет дошёл до целевой стороны
            if self.me != self.target:
                final = self._clone(pkt, stage + 1, route_add=self.target)
                send_packet(self.peers[self.target], json.dumps(final).encode())
            else:
                self.received.append(pkt)
                log.info("delivered id=%s via %s", pid[:8], pkt["route"])

    # ---------------------------------------------------------------- intern
    def _fanout(
        self,
        base: dict,
        fanout: int,
        exclude: Set[str],
        stage_override: int | None = None,
    ) -> None:
        recips = [u for u in self.peers if u not in exclude]
        for r in random.sample(recips, min(fanout, len(recips))):
            pkt = self._clone(base, stage_override or base["stage"], route_add=r)
            send_packet(self.peers[r], json.dumps(pkt).encode())

    # helpers
    def _make_packet(self, target: str, stage: int, security: dict | None = None) -> dict:
        return {
            "id": uuid.uuid4().hex,
            "src": self.me,
            "target": target,
            "stage": stage,
            "route": [self.me],
            "security": security or {},
        }

    @staticmethod
    def _clone(p: dict, stage: int, route_add: str | None = None) -> dict:
        q = deepcopy(p)
        q["stage"] = stage
        if route_add:
            q["route"].append(route_add)
        return q
