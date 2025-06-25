from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton

class ConnectDialog(QDialog):
    def __init__(self, parent=None, initiator=None, route=None, orchestrator=None):
        super().__init__(parent)
        # Устанавливаем заголовок окна
        self.setWindowTitle("Запрос на соединение")
        self.orchestrator = orchestrator

        # Создаем основной вертикальный layout
        layout = QVBoxLayout(self)

        # Метка маршрута (соединяем узлы стрелками "→")
        route_str = " → ".join(route) if route else ""
        route_label = QLabel(f"Маршрут: {route_str}")
        layout.addWidget(route_label)

        # Метка информации об инициаторе (имя пользователя и IP-адрес)
        initiator_name = initiator.get("username", "") if initiator else ""
        initiator_ip = initiator.get("ip", "") if initiator else ""
        initiator_label = QLabel(f"Инициатор: {initiator_name} ({initiator_ip})")
        layout.addWidget(initiator_label)

        # Горизонтальный layout для кнопок
        buttons_layout = QHBoxLayout()
        accept_button = QPushButton("Принять")
        decline_button = QPushButton("Отклонить")
        buttons_layout.addWidget(accept_button)
        buttons_layout.addWidget(decline_button)
        layout.addLayout(buttons_layout)

        # Подключаем сигналы нажатия кнопок к обработчикам
        accept_button.clicked.connect(self.on_accept)
        decline_button.clicked.connect(self.on_reject)

        # Автоматически запускаем первые шаги рукопожатия (главы 1–8) через Orchestrator
        if self.orchestrator is not None:
            try:
                # Предполагается, что Orchestrator имеет метод для начальных этапов handshake
                if hasattr(self.orchestrator, "start_handshake"):
                    self.orchestrator.start_handshake()       # Запуск глав 1–8
                elif hasattr(self.orchestrator, "startHandshake"):
                    self.orchestrator.startHandshake()       # Вариант имени метода с большой буквы
                # Если метод назван иначе, можно вызывать соответствующий (например, orchestrator.process_handshake(1,8))
            except Exception as e:
                print(f"Ошибка при запуске начальных шагов handshake: {e}")

    def on_accept(self):
        """Обработчик нажатия кнопки 'Принять'."""
        # Продолжаем процесс рукопожатия (главы 9–12) через Orchestrator
        if self.orchestrator is not None:
            try:
                if hasattr(self.orchestrator, "continue_handshake"):
                    self.orchestrator.continue_handshake()   # Продолжение handshake (главы 9–12)
                elif hasattr(self.orchestrator, "continueHandshake"):
                    self.orchestrator.continueHandshake()
                elif hasattr(self.orchestrator, "finish_handshake"):
                    self.orchestrator.finish_handshake()
            except Exception as e:
                print(f"Ошибка при продолжении handshake: {e}")
        # Закрываем диалог с положительным результатом
        self.accept()

    def on_reject(self):
        """Обработчик нажатия кнопки 'Отклонить'."""
        # Прерываем процесс соединения/handshake через Orchestrator (или напрямую через контекст)
        if self.orchestrator is not None:
            try:
                if hasattr(self.orchestrator, "abort"):
                    self.orchestrator.abort()               # Прерывание соединения
                elif hasattr(self.orchestrator, "stop"):
                    self.orchestrator.stop()
                # Если Orchestrator содержит объект контекста с методом abort
                elif hasattr(self.orchestrator, "context") and hasattr(self.orchestrator.context, "abort"):
                    self.orchestrator.context.abort()
            except Exception as e:
                print(f"Ошибка при отмене соединения: {e}")
        # Закрываем диалог с отрицательным результатом
        self.reject()
