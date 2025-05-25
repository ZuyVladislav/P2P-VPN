# -*- coding: utf-8 -*-
"""
network.transport — низкоуровневый UDP-транспорт + helper connect_to_peer()

• send_packet()            — fire-and-forget отправка UDP-датаграммы.
• start_listener() / stop_listener()  — общий UDP-слушатель *с поддержкой
  нескольких callback-ов* (fan-out полученных пакетов).
• UDPListener              — удобный контекст-менеджер.
• connect_to_peer()        — high-level заглушка, использующая crypto.ikev2_*.
"""
from __future__ import annotations

import logging
import socket
import threading
from collections import defaultdict
from contextlib import closing, suppress
from types import TracebackType
from typing import Callable, Optional, Type, Tuple

from config import DEFAULT_PORT

# ─────────────────────────────────────────────────────────────────────────────
_LOG = logging.getLogger(__name__)

# внутренние глобалы
_RECV_SOCKET: Optional[socket.socket] = None
_LISTENER_THREAD: Optional[threading.Thread] = None
_SHUTDOWN = threading.Event()
_LOCK = threading.Lock()

# порт → список callback-ов
_CALLBACKS: dict[int, list[Callable[[bytes, str], None]]] = defaultdict(list)

# =============================================================================
# 1. Одноразовая отправка UDP-пакета
# =============================================================================
def send_packet(ip: str, data: bytes, port: int = DEFAULT_PORT) -> None:
    """Open-send-close (UDP fire-and-forget)."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
        try:
            sock.sendto(data, (ip, port))
            _LOG.debug("→ %s:%s  %d bytes", ip, port, len(data))
        except OSError as exc:
            _LOG.warning("send_packet(%s:%s) failed: %s", ip, port, exc)

# =============================================================================
# 2. Фоновый слушатель с несколькими callback-ами
# =============================================================================
def start_listener(
    on_receive: Callable[[bytes, str], None],
    port: int = DEFAULT_PORT,
    *,
    timeout: float = 0.5,
) -> None:
    """
    Регистрирует *on_receive* и (при необходимости) поднимает общий
    UDP-listener.  Поддерживается **неограниченное** число callback-ов.
    """
    global _RECV_SOCKET, _LISTENER_THREAD

    with _LOCK:
        # регистрируем callback
        _CALLBACKS[port].append(on_receive)

        # если уже работает — ничего больше делать не нужно
        if _LISTENER_THREAD and _LISTENER_THREAD.is_alive():
            return

        _SHUTDOWN.clear()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with suppress(AttributeError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # не на всех ОС

        sock.bind(("", port))
        sock.settimeout(timeout)
        _RECV_SOCKET = sock

        def _listen() -> None:
            _LOG.info("listener started on UDP *:%s", port)
            while not _SHUTDOWN.is_set():
                try:
                    data, addr = sock.recvfrom(65_507)  # max UDP payload
                except socket.timeout:
                    continue            # проверяем флаг _SHUTDOWN
                except OSError:
                    break               # сокет закрыт
                ip = addr[0]
                _LOG.debug("← %s  %d bytes", ip, len(data))

                # fan-out на все зарегистрированные callback-и
                for cb in list(_CALLBACKS[port]):
                    try:
                        cb(data, ip)
                    except Exception:   # pragma: no cover — логируем стектрейс
                        _LOG.exception("error in on_receive()")
            _LOG.info("listener stopped")

        _LISTENER_THREAD = threading.Thread(
            target=_listen, daemon=True, name="udp-listener"
        )
        _LISTENER_THREAD.start()

# -----------------------------------------------------------------------------
def stop_listener(join: bool = True) -> None:
    """
    Остановить общий слушатель (graceful-shutdown).

    **ВНИМАНИЕ**: останавливает *все* callback-и на данном порту.
    """
    global _RECV_SOCKET

    with _LOCK:
        if not _RECV_SOCKET:
            return
        _SHUTDOWN.set()
        try:
            _RECV_SOCKET.close()
        finally:
            _RECV_SOCKET = None
        # очистка списка callback-ов
        _CALLBACKS.pop(DEFAULT_PORT, None)

    if join and _LISTENER_THREAD:
        _LISTENER_THREAD.join(timeout=1.0)

# =============================================================================
# 3. Контекст-менеджер «with UDPListener(cb): …»
# =============================================================================
class UDPListener:
    """Контекст: запускает listener в __enter__, останавливает в __exit__."""

    def __init__(self, on_receive: Callable[[bytes, str], None], port: int = DEFAULT_PORT):
        self._on_receive = on_receive
        self._port = port

    # -------------------------------------------------------------- context API
    def __enter__(self) -> "UDPListener":
        start_listener(self._on_receive, self._port)
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> bool:
        stop_listener()
        return False  # не подавляем исключения

# =============================================================================
# 4. Высокоуровневое подключение (используется GUI)
# =============================================================================
def connect_to_peer(
    ip: str,
    port: int,
    username: str,
    stop_event: threading.Event,
) -> Tuple[bool, str]:
    """
    Мини-обёртка, делегирующая настоящую криптографию в crypto.ikev2_handshake.

    Возвращает (ok, human-readable-message).
    """
    if stop_event.is_set():
        return False, "Отменено пользователем"

    try:
        from crypto.ikev2_handshake import perform_handshake  # type: ignore
    except ImportError:
        _LOG.warning("crypto.ikev2_handshake not implemented – stub result returned")
        return False, "Модуль шифрования не собран"

    ok, detail = perform_handshake(ip, port, stop_event)
    return ok, ("Соединение успешно" if ok else detail)
