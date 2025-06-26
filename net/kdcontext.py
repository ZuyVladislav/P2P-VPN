class KDContext:
    """
    KDContext хранит контекст одного ключевого обмена: идентификатор удалённого узла,
    сокет соединения и при необходимости handshake_id.
    """
    def __init__(self, remote_id: str, socket_obj):
        self.remote_id = remote_id
        self.socket = socket_obj
        self.handshake_id = None
        self._initial_data = b""

    def feed_initial_data(self, data: bytes):
        """Сохранить начальные данные, полученные до начала обработки handshake."""
        self._initial_data = data

    def abort(self):
        """Прервать текущее соединение (закрыть сокет)."""
        try:
            self.socket.close()
        except Exception:
            pass