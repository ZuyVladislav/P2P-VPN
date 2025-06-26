
# main.py
```python
import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog
from ui import LoginWindow, MainWindow   # импорт классов окон
from net.orchestrator import Orchestrator
from utils.users import USERS
from net.network_thread import NetworkThread

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    # 1. Отобразить окно входа (логин)
    login_window = LoginWindow()
    result = login_window.exec_()
    if result != QDialog.Accepted:
        # Если диалог закрыт без успешного логина, завершаем приложение
        sys.exit(0)
    # 2. Получить выбранного пользователя из словаря USERS
    username = login_window.get_username()
    current_user = USERS.get(username)
    if not current_user:
        sys.exit(0)
    # 3. Инициализировать Orchestrator для текущего пользователя
    orchestrator = Orchestrator(current_user)
    # 4. Создать главное окно, передав ему пользователя (логин) и orchestrator
    main_window = MainWindow(current_user, orchestrator)
    main_window.show()
    # 5. Запустить сетевой поток для прослушивания входящих соединений
    net_thread = NetworkThread(port=5000, current_user=current_user)
    # Привязать сигнал входящего запроса к слоту главного окна
    net_thread.incoming_request.connect(main_window.on_incoming_request)
    # Сохранить поток в объекте главного окна для доступа из UI
    main_window.net_thread = net_thread
    # Передать сетевой поток в orchestrator (на случай исходящих операций через сеть)
    orchestrator.set_network_thread(net_thread)
    net_thread.start()
    # 6. Запустить главный цикл приложения
    sys.exit(app.exec_())