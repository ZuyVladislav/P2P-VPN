import sys
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QDialog
from ui import LoginWindow, MainWindow  # импорт классов окон из пакета ui
from net.orchestrator import Orchestrator  # импорт класса Orchestrator из сетевого модуля
from utils.users import USERS             # импорт словаря пользователей

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    # 1. Отобразить окно входа (логин)
    login_window = LoginWindow()
    result = login_window.exec_()            # открыть LoginWindow как модальный диалог
    if result != QDialog.Accepted:
        # Если диалог закрыт без успешного логина, завершаем приложение
        sys.exit(0)
    # 2. Получить текущего пользователя из словаря USERS
    username = login_window.get_username()   # допустим, LoginWindow предоставляет метод для получения введённого логина
    current_user = USERS.get(username)
    # 3. Инициализировать оркестратор на основе текущего пользователя
    orchestrator = Orchestrator(current_user)
    # 4. Создать и показать главное окно, передав ему пользователя и оркестратор
    main_window = MainWindow(current_user, orchestrator)
    main_window.show()
    # 5. Запустить главный цикл приложения
    sys.exit(app.exec_())