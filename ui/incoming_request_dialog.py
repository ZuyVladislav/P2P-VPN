# -*- coding: utf-8 -*-
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QHBoxLayout,
)


class IncomingRequestDialog(QDialog):
    """Диалог-вопрос «peer хочет установить с вами соединение»."""

    def __init__(self, peer_name: str, parent=None):
        super().__init__(parent, flags=Qt.Dialog | Qt.WindowTitleHint)
        self.setWindowTitle("Запрос на соединение")
        self.resize(320, 120)

        lbl = QLabel(f"Абонент <b>{peer_name}</b> запрашивает соединение")
        lbl.setAlignment(Qt.AlignCenter)

        btn_yes = QPushButton("Принять")
        btn_no = QPushButton("Отклонить")

        h = QHBoxLayout()
        h.addWidget(btn_yes)
        h.addWidget(btn_no)

        v = QVBoxLayout(self)
        v.addWidget(lbl)
        v.addLayout(h)

        btn_yes.clicked.connect(self.accept)   # код 0
        btn_no.clicked.connect(self.reject)    # код 1