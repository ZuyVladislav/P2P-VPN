from __future__ import annotations

__all__ = [
    "LoginDialog",
    "NetworkView",
    "ConnectDialog",
    "IncomingRequestDialog",
    "ChatWindow",
]

from .login_dialog import LoginDialog            # окно авторизации
from .network_view import NetworkView            # список абонентов
from .connect_dialog import ConnectDialog        # диалог «Соединение…»
from .incoming_request_dialog import IncomingRequestDialog   # запрос на соединение
from .chat_window import ChatWindow              # окно чата
