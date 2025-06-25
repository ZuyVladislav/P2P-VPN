from PyQt5.QtWidgets import QMainWindow, QWidget, QLabel, QTableWidget, QTableWidgetItem, QPushButton, QTextEdit, \
    QHBoxLayout, QVBoxLayout, QMessageBox, QAbstractItemView
from PyQt5.QtCore import QObject, pyqtSignal, Qt
import logging
from ui.connect_dialog import ConnectDialog
from utils.users import USERS

class LogHandler(logging.Handler, QObject):
    """Custom logging handler that emits log records to a QTextEdit via a Qt signal."""
    new_log = pyqtSignal(str)
    def __init__(self):
        logging.Handler.__init__(self)
        QObject.__init__(self)
    def emit(self, record):
        msg = self.format(record)
        self.new_log.emit(msg)

class MainWindow(QMainWindow):
    def __init__(self, current_user: str, orchestrator, parent=None):
        super(MainWindow, self).__init__(parent)
        self.current_user = current_user
        self.orchestrator = orchestrator

        self.setWindowTitle(f"Протокол Handshake – Пользователь {current_user}")
        self.resize(600, 400)

        # Центральный виджет и основной layout
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Метка с именем текущего пользователя
        user_label = QLabel(f"Текущий пользователь: {self.current_user}")
        user_label.setStyleSheet("font-weight: bold;")
        main_layout.addWidget(user_label)

        # Таблица других пользователей
        other_users = [u for u in USERS.keys() if u != self.current_user]
        self.user_table = QTableWidget(len(other_users), 3)
        self.user_table.setHorizontalHeaderLabels(["Пользователь", "Статус", ""])
        self.user_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.user_table.setSelectionMode(QAbstractItemView.NoSelection)

        # Заполняем таблицу данными о пользователях
        # Предполагаем, что оркестратор может предоставить список онлайн-узлов
        try:
            online_peers = set(self.orchestrator.get_online_peers())
        except AttributeError:
            online_peers = set()  # если метод недоступен, считаем всех офлайн (или все онлайн по умолчанию)
        for row, user in enumerate(other_users):
            # Имя
            self.user_table.setItem(row, 0, QTableWidgetItem(user))
            # Статус (онлайн/офлайн)
            status = "В сети" if user in online_peers else "Не в сети"
            status_item = QTableWidgetItem(status)
            self.user_table.setItem(row, 1, status_item)
            # Кнопка "Соединиться"
            btn = QPushButton("Соединиться")
            btn.setEnabled(status == "В сети")
            btn.clicked.connect(lambda _, u=user: self.on_connect_clicked(u))
            self.user_table.setCellWidget(row, 2, btn)
        main_layout.addWidget(self.user_table)

        # Поле для вывода журнала (логов) handshake-процесса
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setPlaceholderText("Журнал handshake-процесса...")
        main_layout.addWidget(self.log_edit)

        # Панель с кнопками "Проверить абонентов" и "Выход"
        btn_panel = QHBoxLayout()
        self.refresh_btn = QPushButton("Проверить абонентов")
        self.refresh_btn.clicked.connect(self.on_check_subscribers)
        btn_panel.addWidget(self.refresh_btn)
        btn_panel.addStretch(1)  # раздвигает кнопки по сторонам
        self.exit_btn = QPushButton("Выход")
        self.exit_btn.clicked.connect(self.close)
        btn_panel.addWidget(self.exit_btn)
        main_layout.addLayout(btn_panel)

        # Настраиваем logging: подключаем наш обработчик к QTextEdit
        self.log_handler = LogHandler()
        self.log_handler.new_log.connect(self.log_edit.append)
        log_format = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
        self.log_handler.setFormatter(log_format)
        logging.getLogger().addHandler(self.log_handler)
        logging.getLogger().setLevel(logging.DEBUG)

    def on_connect_clicked(self, target_user: str):
        """Запрос на установление соединения с выбранным пользователем."""
        dialog = ConnectDialog(target_user, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            try:
                self.orchestrator.initiate_handshake(target_user)
            except Exception as e:
                QMessageBox.critical(self, "Ошибка",
                                     f"Не удалось подключиться:\n{e.__class__.__name__}: {e}")

    def on_check_subscribers(self):
        """Обновление статусов (онлайн/офлайн) других пользователей, по запросу."""
        if hasattr(self.orchestrator, "check_peers"):
            # Если оркестратор поддерживает явную проверку узлов сети
            self.orchestrator.check_peers()
        # Обновим таблицу статусов на основе текущих данных оркестратора
        try:
            online_peers = set(self.orchestrator.get_online_peers())
        except AttributeError:
            online_peers = set()
        for row in range(self.user_table.rowCount()):
            user = self.user_table.item(row, 0).text()
            if user in online_peers:
                self.user_table.item(row, 1).setText("В сети")
                # Активируем кнопку, если ранее была выключена
                cell_widget = self.user_table.cellWidget(row, 2)
                if cell_widget:
                    cell_widget.setEnabled(True)
            else:
                self.user_table.item(row, 1).setText("Не в сети")
                cell_widget = self.user_table.cellWidget(row, 2)
                if cell_widget:
                    cell_widget.setEnabled(False)

    def closeEvent(self, event):
        """Обработчик закрытия главного окна."""
        logging.getLogger().removeHandler(self.log_handler)
        logging.shutdown()
        event.accept()