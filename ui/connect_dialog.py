# -*- coding: utf-8 -*-
"""
ui.connect_dialog — всплывающие окна, связанные с установлением соединения.

• ConnectDialog — индикатор исходящего подключения.
• IncomingRequestDialog — вопрос получателю “принять / отклонить”.

Реальный обмен пакетами сводится к простым сообщениям:
CONNECT_REQ, CONNECT_ACCEPT, CONNECT_DECLINE (см. network.packet).
"""
from __future__ import annotations

import json
import threading
from typing import Callable

from PyQt5.QtCore import pyqtSignal, Qt, QObject
from PyQt5.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QLabel,
    QPushButton,
    QProgressBar,
    QHBoxLayout,
)

from network.packet import CONNECT_REQ, CONNECT_ACCEPT, CONNECT_DECLINE
from network.transport import send_packet, start_listener


# ─────────────────────────────────────────────────────────────────────────────
class HandshakeWorker(QObject):
    """Выполняет mini-handshake в фоне и отдаёт результат сигналом finished."""
    finished = pyqtSignal(bool, str)          # success, message

    def __init__(self, ip: str, port: int, username: str):
        super().__init__()
        self._ip = ip
        self._port = port
        self._username = username
        self._stop = threading.Event()

    # ---------------------------------------------------------------- start
    def start(self, on_ready: Callable[[Callable[[], None]], None]) -> None:
        """Запустить поток и передать stop-колбэк в on_ready()."""

        def _run() -> None:
            # 1. шлём CONNECT_REQ
            pkt = json.dumps(
                {"type": CONNECT_REQ, "from": self._username}
            ).encode()
            send_packet(self._ip, pkt, self._port)

            # 2. ждём CONNECT_ACCEPT / DECLINE
            accepted: bool | None = None
            waiter = threading.Event()

            def _rx(data: bytes, _addr: str):
                nonlocal accepted
                try:
                    obj = json.loads(data.decode(errors="ignore"))
                    tp = obj.get("type")
                    if tp == CONNECT_ACCEPT:
                        accepted = True
                        waiter.set()
                    elif tp == CONNECT_DECLINE:
                        accepted = False
                        waiter.set()
                except Exception:
                    pass  # игнорируем мусор

            # регистрируем ЕЩЁ один callback — общий listener уже умеет fan-out
            start_listener(_rx, self._port)

            waiter.wait(5.0)            # 5 с на ответ удалённого узла

            # 3. формируем результат
            if self._stop.is_set():
                self.finished.emit(False, "Отменено пользователем")
            elif accepted is None:
                self.finished.emit(False, "Нет ответа от удалённого узла")
            elif accepted:
                self.finished.emit(True, "Соединение успешно")
            else:
                self.finished.emit(False, "Удалённый узел отклонил запрос")

        threading.Thread(target=_run, daemon=True, name="handshake").start()
        on_ready(self.stop)

    # ---------------------------------------------------------------- stop
    def stop(self) -> None:                 # вызывается при «Отменить»
        self._stop.set()


# ─────────────────────────────────────────────────────────────────────────────
class ConnectDialog(QDialog):
    """Окно-индикатор «Установление соединения …»."""

    connectionReady = pyqtSignal(str, int)      # ip, port

    def __init__(self, ip: str, port: int, username: str, parent=None):
        super().__init__(parent)
        self._ip = ip
        self._port = port

        self.setWindowTitle(f"Соединение с {username}")
        self.resize(340, 140)

        self._lbl = QLabel("Установление соединения…", alignment=Qt.AlignCenter)

        self._bar = QProgressBar()
        self._bar.setRange(0, 0)                # «крутилка»

        self._btn = QPushButton("Отменить")

        v = QVBoxLayout(self)
        v.addWidget(self._lbl)
        v.addWidget(self._bar)
        v.addWidget(self._btn)

        # запускаем worker
        self._worker = HandshakeWorker(ip, port, username)
        self._worker.start(lambda stopper: self._btn.clicked.connect(stopper))
        self._worker.finished.connect(self._on_finished)

    # ---------------------------------------------------------------- handle result
    def _on_finished(self, ok: bool, msg: str) -> None:
        self._lbl.setText(msg)
        self._bar.setRange(0, 1)            # стоп анимации

        self._btn.clicked.disconnect()      # type: ignore[arg-type]
        if ok:
            self._btn.setText("Открыть чат")
            self._btn.clicked.connect(
                lambda: self.connectionReady.emit(self._ip, self._port)
            )
        else:
            self._btn.setText("Закрыть")
            self._btn.clicked.connect(self.reject)


# ─────────────────────────────────────────────────────────────────────────────
class IncomingRequestDialog(QDialog):
    """Вопрос получателю: «Соединиться / Отклонить». Мини-реализация."""

    def __init__(self, peer_name: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Входящий запрос")
        self.setModal(True)
        self.resize(360, 120)

        label = QLabel(
            f"Абонент <b>{peer_name}</b> хочет установить с вами соединение",
            alignment=Qt.AlignCenter,
        )

        btn_yes = QPushButton("Соединиться")
        btn_no = QPushButton("Отклонить")
        btn_yes.clicked.connect(self.accept)
        btn_no.clicked.connect(self.reject)

        h = QHBoxLayout()
        h.addStretch(1)
        h.addWidget(btn_yes)
        h.addWidget(btn_no)
        h.addStretch(1)

        v = QVBoxLayout(self)
        v.addWidget(label)
        v.addLayout(h)


# ─────────────────────────────────────────────────────────────────────────────
__all__ = ["ConnectDialog", "IncomingRequestDialog"]
