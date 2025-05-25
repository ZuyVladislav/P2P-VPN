# -*- coding: utf-8 -*-
"""
Обнаружение пиров в ЛВС + оболочка-адаптер McastDiscovery для GUI.

• discover_peers() — активный широковещательный опрос
• DiscoveryResponder  — пассивный автоответчик
• McastDiscovery      — QObject-обёртка, которую ждёт ui.network_view:
      - start() / stop()
      - сигнал peerFound(str ip, int port)

Если нужна «настоящая» логика, правьте только discover_peers() —
McastDiscovery просто оборачивает её в поток и шлёт сигнал в Qt.
"""
from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Dict, List, Set

from PyQt5.QtCore import QObject, pyqtSignal

from config import BROADCAST_PORT, DEFAULT_PORT

log = logging.getLogger(__name__)

_DISCOVERY_REQUEST = b"DISCOVER_REQUEST"
_DISCOVERY_RESPONSE = b"DISCOVER_RESPONSE:"

# ────────────────────────────────────────────────────────────────────────────
# 1. Активный поиск пиров (UDP-broadcast)
# ────────────────────────────────────────────────────────────────────────────
def discover_peers(
    timeout: float = 2.0,
    bcasts: List[str] | None = None,
) -> Dict[str, str]:
    """
    Отправить DISCOVER_REQUEST и ждать ответы *timeout* секунд.

    Returns:
        {username: ip}
    """
    if bcasts is None:
        bcasts = ["255.255.255.255"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)

        for bc in bcasts:
            sock.sendto(_DISCOVERY_REQUEST, (bc, BROADCAST_PORT))

        peers: Dict[str, str] = {}
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                break

            if data.startswith(_DISCOVERY_RESPONSE):
                username = data[len(_DISCOVERY_RESPONSE) :].decode(errors="ignore")
                peers[username] = addr[0]
    finally:
        sock.close()
    return peers


# ────────────────────────────────────────────────────────────────────────────
# 2. Пассивный автоответчик (каждый узел держит свой)
# ────────────────────────────────────────────────────────────────────────────
class DiscoveryResponder(threading.Thread):
    """Слушает BROADCAST_PORT и отвечает DISCOVER_RESPONSE:<username>"""

    def __init__(self, username: str):
        super().__init__(daemon=True, name=f"discovery-{username}")
        self.username = username

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # SO_REUSEPORT (не везде есть)
        _opt = getattr(socket, "SO_REUSEPORT", None)
        if _opt is not None:
            self._sock.setsockopt(socket.SOL_SOCKET, _opt, 1)

        self._sock.bind(("", BROADCAST_PORT))
        self._sock.settimeout(0.5)
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------
    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:  # сокет закрыт
                break

            if data == _DISCOVERY_REQUEST:
                payload = _DISCOVERY_RESPONSE + self.username.encode()
                try:
                    self._sock.sendto(payload, addr)
                except OSError as exc:
                    log.warning("Failed to send discovery response: %s", exc)

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._sock.close()
        except OSError:
            pass


# ────────────────────────────────────────────────────────────────────────────
# 3. QObject-обёртка для PyQt5 — именно её ждёт ui.network_view
# ────────────────────────────────────────────────────────────────────────────
class McastDiscovery(QObject):
    """
    Обёртка над discover_peers() для использования в Qt-GUI.

    peerFound(str ip, int port) — сигнал при каждом новом найденном узле.
    """

    peerFound = pyqtSignal(str, int)

    def __init__(
        self,
        interval: float = 3.0,
        broadcast_addrs: List[str] | None = None,
        parent: QObject | None = None,
    ):
        super().__init__(parent)
        self._interval = interval
        self._bcasts = broadcast_addrs
        self._running = False
        self._thread: threading.Thread | None = None
        self._known: Set[str] = set()  # ip-адреса, уже сообщённые в GUI

    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    # ------------------------------------------------------------------
    def _worker(self) -> None:
        while self._running:
            peers = discover_peers(timeout=self._interval, bcasts=self._bcasts)
            for ip in peers.values():
                if ip not in self._known:
                    self._known.add(ip)
                    # в примере порт фиксированный, измените при необходимости
                    self.peerFound.emit(ip, DEFAULT_PORT)
            # небольшой сон чтобы не «крутить» CPU, discover_peers уже ждёт
            time.sleep(0.1)
