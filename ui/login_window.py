from PyQt5.QtWidgets import (
    QDialog, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QHBoxLayout, QMessageBox
)
from utils.users import USERS  # словарь {логин: данные пользователя}

class LoginWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        # Настройка окна
        self.setWindowTitle("Вход в систему")
        self.setModal(True)               # делаем окно модальным
        self.setFixedSize(300, 150)       # фиксированный компактный размер

        # Создание виджетов
        self.label_login = QLabel("Логин:")
        self.label_password = QLabel("Пароль:")
        self.login_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)  # скрывать ввод пароля
        self.login_button = QPushButton("Войти")

        # Размещение виджетов в компоновке
        h_layout1 = QHBoxLayout()
        h_layout1.addWidget(self.label_login)
        h_layout1.addWidget(self.login_input)
        h_layout2 = QHBoxLayout()
        h_layout2.addWidget(self.label_password)
        h_layout2.addWidget(self.password_input)
        v_layout = QVBoxLayout()
        v_layout.addLayout(h_layout1)
        v_layout.addLayout(h_layout2)
        v_layout.addWidget(self.login_button)
        self.setLayout(v_layout)

        # Подключение сигналов и слотов
        self.login_button.clicked.connect(self.tryLogin)
        # Обработка клавиши Enter: на логине -> фокус на пароль, на пароле -> попытка входа
        self.login_input.returnPressed.connect(lambda: self.password_input.setFocus())
        self.password_input.returnPressed.connect(self.tryLogin)

    def tryLogin(self):
        """Проверяет корректность введённых данных и выполняет вход."""
        username = self.login_input.text().strip()
        password = self.password_input.text()
        if username in USERS and USERS[username]["password"] == password:
            # Успешный вход: закрыть диалог с результатом Accepted
            self.accept()
        else:
            # Ошибка авторизации: показать сообщение и оставить диалог открытым
            QMessageBox.critical(self, "Ошибка", "Неверный логин или пароль")

    def get_username(self) -> str:
        """Возвращает введённый логин пользователя."""
        return self.login_input.text().strip()