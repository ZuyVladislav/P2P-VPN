import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog
from ui import LoginWindow, MainWindow   # импорт классов окон из пакета ui
from net.orchestrator import Orchestrator  # импорт класса Orchestrator из сетевого модуля
from utils.users import USERS              # импорт словаря пользователей
from net.network_thread import NetworkThread  # импорт класса сетевого потока для входящих соединений

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    # 1. Отобразить окно входа (логин)
    login_window = LoginWindow()
    result = login_window.exec_()  # открыть LoginWindow как модальный диалог
    if result != QDialog.Accepted:
        # Если диалог закрыт без успешного логина, завершаем приложение
        sys.exit(0)
    # 2. Получить текущего пользователя из словаря USERS
    username = login_window.get_username()   # метод получения введённого логина
    current_user = USERS.get(username)
    # 3. Инициализировать оркестратор на основе текущего пользователя
    orchestrator = Orchestrator(current_user)
    # 4. Создать главное окно, передав ему пользователя и оркестратор
    main_window = MainWindow(current_user, orchestrator)
    main_window.show()  # показать главное окно приложения
    # 5. Запустить сетевой поток для прослушивания входящих соединений
    net_thread = NetworkThread(port=5000)
    # Привязать сигнал поступающего запроса к слоту главного окна
    net_thread.incoming_request.connect(main_window.on_incoming_request)
    # Сохранить поток в объекте главного окна, чтобы иметь к нему доступ из UI
    main_window.net_thread = net_thread
    net_thread.start()
    # 6. Запустить главный цикл приложения
    sys.exit(app.exec_())