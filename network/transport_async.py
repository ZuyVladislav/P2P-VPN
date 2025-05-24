# network/transport_async.py
# -*- coding: utf-8 -*-
"""
Асинхронный UDP‑транспорт на базе asyncio.DatagramProtocol
"""
import asyncio
from contextlib import asynccontextmanager
from typing import Callable

from config import DEFAULT_PORT


# ──────────────────────────────────────────────────────────────────────────────
class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, on_receive: Callable[[bytes, str], None]):
        self._on_receive = on_receive

    def datagram_received(self, data: bytes, addr):
        ip, _ = addr
        self._on_receive(data, ip)


# ------------------------------------------------------------------------------
async def send_packet(
    ip: str,
    data: bytes,
    port: int = DEFAULT_PORT,
) -> None:
    """
    Одноразовая отправка UDP‑пакета (создаём транспорт → send → close).
    """
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol,
        remote_addr=(ip, port),
    )
    transport.sendto(data)
    transport.close()


# ------------------------------------------------------------------------------
async def open_listener(
    on_receive: Callable[[bytes, str], None],
    port: int = DEFAULT_PORT,
    *,
    reuse_port: bool = True,
):
    """
    Поднимает приёмник, возвращает transport; .close() — остановка.
    """
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _Protocol(on_receive),
        local_addr=("0.0.0.0", port),
        reuse_port=reuse_port,
    )
    return transport


# ------------------------------------------------------------------------------
@asynccontextmanager
async def udp_listener(on_receive, port: int = DEFAULT_PORT):
    """
    async with udp_listener(cb): …  — автоматически откроет/закроет сокет.
    """
    transport = await open_listener(on_receive, port)
    try:
        yield transport
    finally:
        transport.close()