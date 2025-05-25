# -*- coding: utf-8 -*-
"""
Асинхронная реализация алгоритма «множественных стартовых соединений»
(пункт 2.1 ТЗ).

* Без блокирующих вызовов ― только asyncio‑корутины;
* Предотвращает дубли пакетов по packet_id (UUID v4);
* Логирует каждую отправку/приём (debug);
* Параметры fan‑out вынесены в словарь и легко настраиваются;
* Для транспорта используется лёгкая обёртка над
  `asyncio.DatagramEndpoint` (UDP, без надстроек над TCP).

Чтобы посмотреть «как это гоняется», запустите файл прямо: он поднимает
два узла в одном процессе и инициирует соединение User1 → User2.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import uuid
from typing import Dict, List, Set, Tuple

__all__ = [
    "UdpTransport",
    "AsyncMultiStartConnector",
]

###############################################################################
#  Настройка логгера
###############################################################################
log = logging.getLogger(__name__)
if not log.hasHandlers():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(levelname).1s %(name)s › %(message)s",
    )

###############################################################################
#  UDP‑транспорт поверх asyncio
###############################################################################

class _DatagramProto(asyncio.DatagramProtocol):
    """Внутренний протокол для получения датаграмм."""

    def __init__(self, queue: "asyncio.Queue[Tuple[bytes, Tuple[str, int]]]"):
        self.queue = queue

    def datagram_received(self, data: bytes, addr):  # noqa: D401
        # передаём наверх и забываем
        self.queue.put_nowait((data, addr))

    def error_received(self, exc):  # noqa: D401
        log.warning("UDP error_received: %s", exc)


class UdpTransport:
    """Мини‑обёртка над UDP‑датаграммами в asyncio.

    * non‑blocking send/recv;
    * `recv()` — корутина, которая резолвится, когда пришли данные.
    """

    def __init__(self, local_port: int, loop: asyncio.AbstractEventLoop | None = None):
        self._loop = loop or asyncio.get_event_loop()
        self._local_port = local_port
        self._rx_queue: "asyncio.Queue[Tuple[bytes, Tuple[str, int]]]" = asyncio.Queue()
        self._transport: asyncio.DatagramTransport | None = None

    async def start(self):
        if self._transport is not None:
            return  # уже запущено
        self._transport, _ = await self._loop.create_datagram_endpoint(
            lambda: _DatagramProto(self._rx_queue),
            local_addr=("0.0.0.0", self._local_port),
        )
        log.debug("UDP transport started on port %d", self._local_port)

    async def stop(self):
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    # --------------------------------------------------------------------- API
    def send(self, host: str, port: int, data: bytes) -> None:
        """Мгновенная (не блокирующая) отправка пакета."""
        if self._transport is None:
            raise RuntimeError("Transport is not started")
        self._transport.sendto(data, (host, port))

    async def recv(self, timeout: float | None = None) -> Tuple[bytes, Tuple[str, int]]:  # noqa: D401,E501
        """Дождаться входящего пакета.  timeout=None ⇒ ждём вечно."""
        if timeout is None:
            return await self._rx_queue.get()
        return await asyncio.wait_for(self._rx_queue.get(), timeout)


###############################################################################
#  Алгоритм множественных стартов
###############################################################################

class AsyncMultiStartConnector:
    """Асинхронный вариант `MultiStartConnector`.

    Параметры **fan‑out** по стадиям и список узлов передаются в конструкторе,
    сам объект не блокирует поток — всю логику выполняют корутины.
    """

    #: fan‑out по умолчанию: стадия → сколько копий отсылаем дальше
    DEFAULT_FANOUTS = {1: 3, 2: 3, 3: 2}

    def __init__(
        self,
        me: str,
        peers: Dict[str, str],  # username → ip
        transport: UdpTransport,
        fanouts: Dict[int, int] | None = None,
        dst_port: int = 5000,
    ) -> None:
        self.me = me
        self.peers = peers
        self.tx = transport
        self.fanouts = fanouts or self.DEFAULT_FANOUTS
        self.dst_port = dst_port

        self._target: str | None = None
        self._seen_packets: Set[str] = set()

    # ---------------------------------------------------------------- public
    async def start(self, target: str, security: dict | None = None) -> None:
        """Запускает исходящее соединение к *target*.

        Корутиной не ждёт конца доставки: возвращается сразу после fan‑out #1.
        """
        self._target = target
        pkt = self._make_packet(target, stage=1, security=security)
        await self._fanout(pkt, self.fanouts.get(1, 0), exclude={self.me})

    async def pump(self) -> None:
        """Бесконечно принимает входящие пакеты и обрабатывает их."""
        while True:
            data, _addr = await self.tx.recv()
            try:
                pkt = json.loads(data)
            except Exception:
                log.debug("Skip malformed packet (%d bytes)", len(data))
                continue
            await self._handle(pkt)

    # ------------------------------------------------------------ internal
    async def _handle(self, p: dict) -> None:
        pid = p.get("packet_id")
        if not pid or pid in self._seen_packets:
            return  # дубликат или мусор
        self._seen_packets.add(pid)

        stage = p.get("stage", 0)
        target = p.get("target")
        if target != self._target:
            return  # не наш разговор

        log.debug("← packet stage=%s id=%s route=%s", stage, pid, p["route"])

        if stage < 3:
            nxt_stage = stage + 1
            fanout = self.fanouts.get(nxt_stage, 0)
            exclude = {self.me}
            if nxt_stage == 3:
                exclude.add(target)
            await self._fanout(p, fanout, exclude, stage_override=nxt_stage)
        else:
            # финальная доставка
            if self.me != target:
                final = self._clone(p, stage + 1, route_add=target)
                self.tx.send(self.peers[target], self.dst_port, json.dumps(final).encode())
                log.debug("→ final hop to %s id=%s", target, final["packet_id"])
            else:
                log.info("✓ пакеты доставлены! from=%s route=%s", p["src"], p["route"])

    async def _fanout(
        self,
        base_pkt: dict,
        fanout: int,
        exclude: Set[str],
        stage_override: int | None = None,
    ) -> None:
        recips = [u for u in self.peers if u not in exclude]
        k = min(fanout, len(recips))
        if k == 0:
            return
        choice = random.sample(recips, k)
        for r in choice:
            pkt = self._clone(base_pkt, stage_override or base_pkt["stage"], route_add=r)
            self.tx.send(self.peers[r], self.dst_port, json.dumps(pkt).encode())
            log.debug("→ %s stage=%d id=%s", r, pkt["stage"], pkt["packet_id"])

    # ---------------------------------------------------------------- helpers
    def _make_packet(self, target: str, stage: int, security: dict | None = None) -> dict:
        return {
            "packet_id": uuid.uuid4().hex,
            "src": self.me,
            "target": target,
            "stage": stage,
            "route": [self.me],
            "security": security or {},
        }

    def _clone(self, p: dict, stage: int, route_add: str | None = None) -> dict:
        q = dict(p)
        q["stage"] = stage
        if route_add:
            q["route"] = p["route"] + [route_add]
        return q

###############################################################################
#  Demo‑запуск (два узла в одном процессе)
###############################################################################

if __name__ == "__main__":
    async def _demo():
        peers = {
            "User1": "127.0.0.1",
            "User2": "127.0.0.1",
        }
        t1 = UdpTransport(local_port=5000)
        t2 = UdpTransport(local_port=5001)
        await asyncio.gather(t1.start(), t2.start())

        c1 = AsyncMultiStartConnector("User1", peers, t1)
        c2 = AsyncMultiStartConnector("User2", peers, t2)

        # приёмники
        asyncio.create_task(c1.pump())
        asyncio.create_task(c2.pump())

        # инициируем соединение User1 → User2
        await c1.start("User2", security={"algo": "AES256"})

        # ждём, пока всё не разойдётся
        await asyncio.sleep(2)

        await asyncio.gather(t1.stop(), t2.stop())

    asyncio.run(_demo())
