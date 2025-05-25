# -*- coding: utf-8 -*-
"""
ui.chat_window — «живой» UDP-чат между двумя узлами.

• история сообщений (read-only QTextEdit);
• многострочное поле ввода (QTextEdit) + кнопка «Отправить»;
• Enter / Return отправляет сообщение, Shift+Enter даёт новую строку;
• пакеты передаются через network.transport.send_packet() со схемой
  {"type": CHAT_MESSAGE, "from": <me>, "msg": <text>}.
"""
from __future__ import annotations

import json
from datetime import datetime

from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui import QTextOption
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QTextEdit,
    QPushButton,
    QHBoxLayout,
)

from config import DEFAULT_PORT
from network.packet import CHAT_MESSAGE
from network.transport import send_packet, start_listener, stop_listener


# ─────────────────────────────────────────────────────────────────────────────
class _Rx(QObject):
    """Промежуточный объект → сигнал arrives в GUI-поток."""
    arrived = pyqtSignal(str, str)          # sender, text


class ChatWindow(QWidget):
    """Простое окно чата поверх UDP."""

    # ----------------------------------------------------------------── init
    def __init__(
        self,
        me_name: str,
        peer_name: str,
        peer_ip: str,
        peer_port: int = DEFAULT_PORT,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self._me = me_name
        self._peer_name = peer_name
        self._peer_ip = peer_ip
        self._peer_port = peer_port

        self.setWindowTitle(f"Чат с {peer_name}")
        self.resize(480, 380)

        # ───── UI ─────────────────────────────────────────────────────
        self._history = QTextEdit()
        self._history.setReadOnly(True)
        self._history.setWordWrapMode(QTextOption.NoWrap)

        self._edit = QTextEdit()
        self._edit.setFixedHeight(70)
        self._edit.setPlaceholderText("Введите сообщение…")
        self._edit.installEventFilter(self)        # перехватываем Enter

        self._btn_send = QPushButton("Отправить")
        self._btn_send.setDefault(True)            # Enter триггерит кнопку
        self._btn_send.clicked.connect(self._on_send_clicked)

        h = QHBoxLayout()
        h.addWidget(self._edit, 1)
        h.addWidget(self._btn_send)

        v = QVBoxLayout(self)
        v.addWidget(self._history, 1)
        v.addLayout(h)

        self._edit.setFocus()

        # ───── входящие сообщения ────────────────────────────────────
        self._rx = _Rx()
        self._rx.arrived.connect(self._append)

        # глобальный UDP-слушатель (fan-out поддерживается transport.py)
        start_listener(self._udp_on_receive, DEFAULT_PORT)

    # ---------------------------------------------------------------- event filter
    def eventFilter(self, obj, ev):                 # noqa: N802
        if obj is self._edit and ev.type() == ev.KeyPress:
            if ev.key() in (Qt.Key_Return, Qt.Key_Enter) and not ev.modifiers():
                self._on_send_clicked()
                return True      # гасим событие
        return super().eventFilter(obj, ev)

    # ---------------------------------------------------------------- send
    def _on_send_clicked(self) -> None:
        txt = self._edit.toPlainText().strip()
        if not txt:
            return
        self._edit.clear()

        pkt = json.dumps(
            {"type": CHAT_MESSAGE, "from": self._me, "msg": txt}
        ).encode()
        send_packet(self._peer_ip, pkt, self._peer_port)

        self._append(self._me, txt)

    # ---------------------------------------------------------------- recv (background thread)
    def _udp_on_receive(self, data: bytes, _src_ip: str) -> None:
        """Вызывается транспортом *не* в GUI-потоке → пробрасываем сигнал."""
        try:
            obj = json.loads(data.decode(errors="ignore"))
            if obj.get("type") != CHAT_MESSAGE:
                return
            sender = obj.get("from")
            msg = obj.get("msg")
            if sender and msg:
                self._rx.arrived.emit(sender, msg)
        except Exception:
            # игнорируем мусор / неверный JSON
            pass

    # ---------------------------------------------------------------- gui append
    def _append(self, sender: str, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._history.append(f"<b>[{ts}] {sender}:</b> {msg}")
        self._history.verticalScrollBar().setValue(
            self._history.verticalScrollBar().maximum()
        )

    # ---------------------------------------------------------------- close
    def closeEvent(self, event):  # noqa: N802
        """
        При закрытии окна отписываемся от UDP-listener’а.
        Если другие окна ещё открыты, они по-прежнему получают пакеты.
        """
        stop_listener(join=False)
        super().closeEvent(event)
