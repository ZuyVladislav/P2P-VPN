# ui/network_view.py
from __future__ import annotations

import functools
import json
from typing import Dict, List, Tuple

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QPushButton,
    QHeaderView,
)

from config import USERS, DEFAULT_PORT
from network.discovery import discover_peers
from network.transport import start_listener, send_packet
from network.packet import CONNECT_REQ, CONNECT_ACCEPT, CONNECT_DECLINE
from ui.connect_dialog import ConnectDialog
from ui.chat_window import ChatWindow
from ui.incoming_request_dialog import IncomingRequestDialog


# ───────────────────────────────────────────────────────────────────────
# helper-signal: переводим событие из фонового потока в GUI-поток
# ───────────────────────────────────────────────────────────────────────
class _Rx(QObject):
    arrived = pyqtSignal(bytes, str)          # data, ip


# ───────────────────────────────────────────────────────────────────────
# discover_peers worker
# ───────────────────────────────────────────────────────────────────────
class _DiscoverWorker(QThread):
    peersReady = pyqtSignal(dict)             # {username: ip}

    def run(self) -> None:  # noqa: D401
        self.peersReady.emit(discover_peers(timeout=2.0))


# ───────────────────────────────────────────────────────────────────────
# основное окно
# ───────────────────────────────────────────────────────────────────────
class NetworkView(QWidget):
    """Таблица абонентов, проверка онлайн и соединения."""

    peerSelected = pyqtSignal(str, int)       # ip, port (зарезервировано)

    _COL_NAME = 0
    _COL_STATUS = 1
    _COL_BTN = 2

    # ------------------------------------------------------------------ init
    def __init__(self, user_profile: dict | None = None, parent: QWidget | None = None):
        super().__init__(parent)

        self._profile = user_profile or {}
        self._last_peer: Tuple[str, int, str] | None = None

        # ───── заголовки ───────────────────────────────────────────────
        self.setWindowTitle("Список абонентов в сети")

        title = QLabel(
            "Защищенная виртуальная частная сеть на основе технологии одноранговых сетей"
        )
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-weight: bold;")

        self._lbl_count = QLabel(
            f"Ваша виртуальная частная сеть состоит из {len(USERS)} абонентов"
        )
        self._lbl_count.setAlignment(Qt.AlignCenter)

        # ───── таблица ────────────────────────────────────────────────
        self._table = QTableWidget(len(USERS), 3, self)
        self._table.setHorizontalHeaderLabels(["Абонент", "Статус", ""])
        hdr: QHeaderView = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Stretch)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionMode(QTableWidget.NoSelection)

        for row, username in enumerate(USERS):
            # имя
            self._table.setItem(row, self._COL_NAME, QTableWidgetItem(username))

            # статус
            st = QTableWidgetItem("Не проверено")
            st.setData(Qt.UserRole, False)
            self._table.setItem(row, self._COL_STATUS, st)

            # кнопка
            btn = QPushButton("Соединиться")
            btn.setEnabled(False)
            btn.clicked.connect(
                functools.partial(self._on_connect_clicked, username)
            )
            self._table.setCellWidget(row, self._COL_BTN, btn)

        # ───── нижние элементы ────────────────────────────────────────
        self._btn_check = QPushButton("Проверить абонентов на предмет наличия в сети")
        self._btn_check.clicked.connect(self._start_check)

        self._lbl_result = QLabel("")
        self._lbl_result.setAlignment(Qt.AlignCenter)

        # layout
        vbox = QVBoxLayout(self)
        vbox.addWidget(title)
        vbox.addWidget(self._lbl_count)
        vbox.addWidget(self._table, 1)
        vbox.addWidget(self._btn_check)
        vbox.addWidget(self._lbl_result)

        self.resize(640, 430)

        # ───── UDP-слушатель (CONNECT_REQ) ─────────────────────────────
        self._rx = _Rx()
        self._rx.arrived.connect(self._handle_udp)     # GUI-поток
        start_listener(self._on_udp_bg, DEFAULT_PORT)  # фоновая нить

    # ---------------------------------------------------------------- util
    @staticmethod
    def _ip_for(username: str) -> str:
        return USERS[username]["ip"]

    # ---------------------------------------------------------------- discover
    def _start_check(self) -> None:
        self._btn_check.setEnabled(False)
        self._lbl_result.setText("Проверка …")

        self._worker = _DiscoverWorker(self)
        self._worker.peersReady.connect(self._on_peers_ready)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.start()

    def _on_peers_ready(self, peers: Dict[str, str]) -> None:
        online = set(peers.keys())
        offline: List[str] = []

        for row, username in enumerate(USERS):
            is_online = username in online
            ip = peers.get(username, self._ip_for(username))

            st: QTableWidgetItem = self._table.item(row, self._COL_STATUS)
            st.setText("В сети" if is_online else "Не в сети")
            st.setData(Qt.UserRole, is_online)
            st.setForeground(Qt.darkGreen if is_online else Qt.darkRed)

            btn: QPushButton = self._table.cellWidget(row, self._COL_BTN)  # type: ignore
            btn.setEnabled(is_online)
            btn.setProperty("peer_ip", ip)

            if not is_online:
                offline.append(username)

        self._lbl_result.setText(
            "Все абоненты в сети"
            if not offline
            else f"Абоненты {', '.join(offline)} не в сети"
        )
        self._btn_check.setEnabled(True)

    # ---------------------------------------------------------------- outgoing connect
    def _on_connect_clicked(self, username: str) -> None:
        ip = self._ip_for(username)
        port = DEFAULT_PORT
        self._last_peer = (ip, port, username)

        dlg = ConnectDialog(ip, port, username, self)
        dlg.connectionReady.connect(self._open_chat)
        dlg.exec_()

    def _open_chat(self, peer_ip: str, peer_port: int) -> None:
        me = self._profile.get("username", "Me")
        peer_name = next((u for u in USERS if USERS[u]["ip"] == peer_ip), peer_ip)
        ChatWindow(me, peer_name, peer_ip, peer_port, self).show()

    # ---------------------------------------------------------------- UDP (background → GUI)
    def _on_udp_bg(self, data: bytes, ip: str) -> None:
        self._rx.arrived.emit(data, ip)        # пересылаем сигналом

    def _handle_udp(self, data: bytes, src_ip: str) -> None:
        try:
            obj = json.loads(data.decode(errors="ignore"))
        except Exception:
            return
        if obj.get("type") != CONNECT_REQ:
            return

        peer_name = obj.get("from", src_ip)
        dlg = IncomingRequestDialog(peer_name, self)
        accepted = dlg.exec_() == IncomingRequestDialog.Accepted

        reply = {"type": CONNECT_ACCEPT if accepted else CONNECT_DECLINE}
        send_packet(src_ip, json.dumps(reply).encode(), DEFAULT_PORT)

        if accepted:
            self._open_chat(src_ip, DEFAULT_PORT)