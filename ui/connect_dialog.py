from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QHBoxLayout, QPushButton

class ConnectDialog(QDialog):
    def __init__(self, parent=None, target_user: str = ""):
        super().__init__(parent)
        # Устанавливаем заголовок окна
        self.setWindowTitle("Подключение")
        # Основной вертикальный layout
        layout = QVBoxLayout(self)
        # Текст с подтверждением подключения
        prompt_label = QLabel(f"Соединиться с пользователем {target_user}?")
        layout.addWidget(prompt_label)
        # Горизонтальный layout для кнопок
        buttons_layout = QHBoxLayout()
        accept_button = QPushButton("Принять")
        decline_button = QPushButton("Отмена")
        buttons_layout.addWidget(accept_button)
        buttons_layout.addWidget(decline_button)
        layout.addLayout(buttons_layout)
        # Подключаем сигналы кнопок к слотам диалога
        accept_button.clicked.connect(self.accept)
        decline_button.clicked.connect(self.reject)
