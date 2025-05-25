# =============================================================
# ui/login_dialog.py
# =============================================================
"""Окно авторизации (макет 4.3.1)."""
from __future__ import annotations

import socket
from typing import Dict, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
)

from auth import login, AuthError, get_local_ip

__all__ = ["LoginDialog"]


class LoginDialog(QDialog):
    """Диалог авторизации.

    После успешного входа атрибут *user_profile* содержит Dict,
    возвращённый ``auth.login``.
    """

    #: логин по умолчанию (удобно пока тестируем)
    _DEFAULT_LOGIN = "User1"

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(
            "Защищенная виртуальная частная сеть на основе технологии одноранговых сетей — Авторизация"
        )
        self.user_profile: Optional[Dict] = None

        # ─── widgets ───────────────────────────────────────────
        login_lbl = QLabel("Логин:")
        self._login_edit = QLineEdit(self._DEFAULT_LOGIN)

        pass_lbl = QLabel("Пароль:")
        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.Password)

        btn_login = QPushButton("Авторизация")
        btn_login.clicked.connect(self._on_login_clicked)  # type: ignore[arg-type]

        # layout
        vbox = QVBoxLayout(self)
        vbox.addWidget(login_lbl)
        vbox.addWidget(self._login_edit)
        vbox.addWidget(pass_lbl)
        vbox.addWidget(self._pass_edit)
        vbox.addStretch(1)
        h = QHBoxLayout()
        h.addStretch(1)
        h.addWidget(btn_login)
        vbox.addLayout(h)

        self._login_edit.returnPressed.connect(self._pass_edit.setFocus)  # type: ignore[arg-type]
        self._pass_edit.returnPressed.connect(btn_login.click)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    def _on_login_clicked(self):
        username = self._login_edit.text().strip()
        password = self._pass_edit.text()
        client_ip = get_local_ip()
        try:
            self.user_profile = login(username, password, client_ip)
        except AuthError as e:
            QMessageBox.critical(self, "Ошибка авторизации", str(e))
            return
        except socket.error as e:  # network problems
            QMessageBox.critical(self, "Сеть", f"Не удалось определить IP: {e}")
            return

        self.accept()  # success
