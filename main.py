# -*- coding: utf-8 -*-
"""
Главная точка входа VPN-приложения.
"""
import sys
import logging
from PyQt5.QtWidgets import QApplication

from utils import setup_logging

from ui.login_dialog import LoginDialog
from ui.network_view import NetworkView

# 👇 НОВОЕ
from network.discovery import DiscoveryResponder      #  ← 1

def main() -> None:
    setup_logging(logging.DEBUG)
    app = QApplication(sys.argv)

    login_dlg = LoginDialog()
    if login_dlg.exec_() == LoginDialog.Accepted:
        profile = login_dlg.user_profile               # username, ip …

        # ─── запускаем автоответчик на время жизни приложения ─────────────
        responder = DiscoveryResponder(profile["username"])  # ← 2
        responder.start()                                  # ← 3

        win = NetworkView(user_profile=profile)
        win.show()

        # корректно останавливаем поток при выходе из Qt-цикла
        ret = app.exec_()
        responder.stop()                                   # ← 4
        sys.exit(ret)

    sys.exit(0)

if __name__ == "__main__":
    main()