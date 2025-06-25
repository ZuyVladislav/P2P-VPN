import asyncio
import socket


# Библиотека cryptography используется для криптографических операций в SecureConnection.
# (Предполагается, что SecureConnection определен в другом модуле и использует cryptography для шифрования)
# Здесь мы будем пользоваться объектом SecureConnection для шифрования/дешифрования данных.

class Transport:
    """
    Класс Transport обеспечивает абстракцию транспортного уровня (TCP и UDP)
    с поддержкой защищенного соединения через SecureConnection (например, для одноранговой (P2P) сети).
    Он предоставляет унифицированный интерфейс для отправки и получения данных,
    скрывая детали реализации TCP/UDP и шифрования.

    Этот модуль использует asyncio для асинхронного ввода-вывода,
    а для шифрования/дешифрования ожидается использование библиотеки cryptography
    (через объект SecureConnection).

    Класс можно расширить для поддержки входящих подключений (серверный режим):
    - Для TCP: использовать asyncio.start_server для приема входящих соединений
      и оборачивать каждое принятое соединение в экземпляр Transport.
    - Для UDP: использовать сокет, привязанный к локальному адресу (socket.bind),
      и обрабатывать сообщения от нескольких узлов (например, хранить адреса
      и создавать по необходимости отдельные объекты SecureConnection для каждого узла).
    """

    def __init__(self, protocol: str = 'tcp', secure_conn=None):
        """
        Инициализация транспортного объекта.
        :param protocol: 'tcp' или 'udp' для выбора транспортного протокола.
        :param secure_conn: Объект SecureConnection для шифрования/дешифрования (может быть None для нешифрованного режима).
        """
        self.protocol = protocol.lower()
        if self.protocol not in ('tcp', 'udp'):
            raise ValueError("Unsupported protocol, use 'tcp' or 'udp'")
        self.secure_conn = secure_conn  # Объект для шифрования/дешифрования данных
        self.reader = None
        self.writer = None
        self.sock = None
        self._connected = False

    @property
    def connected(self) -> bool:
        """Показывает, установлено ли соединение."""
        return self._connected

    async def connect(self, host: str, port: int):
        """
        Устанавливает соединение с удаленным узлом (асинхронно).
        Для TCP создает StreamReader/StreamWriter, для UDP — создаёт сокет и соединяется с удаленным адресом.
        """
        if self._connected:
            raise RuntimeError("Соединение уже установлено")
        if self.protocol == 'tcp':
            # Устанавливаем TCP-соединение (создаем потоки чтения и записи)
            self.reader, self.writer = await asyncio.open_connection(host, port)
        elif self.protocol == 'udp':
            # Создаем UDP-сокет и "подключаем" его к удаленному узлу (устанавливаем адрес назначения по умолчанию)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setblocking(False)
            try:
                # Можно явно привязаться к локальному адресу/порту, если необходимо (в противном случае ОС выберет порт автоматически)
                # self.sock.bind(('0.0.0.0', 0))
                self.sock.connect((host, port))
            except Exception:
                # В случае ошибки подключения, закрываем сокет и пробрасываем исключение
                self.sock.close()
                self.sock = None
                raise
        self._connected = True

    async def send(self, data: bytes):
        """
        Отправляет данные на удаленный узел.
        Перед отправкой данные шифруются (если задан secure_conn).
        Для TCP отправляет данные через StreamWriter, для UDP — через сокет (один датаграм).
        """
        if not self._connected:
            raise RuntimeError("Соединение не установлено")
        # Шифрование данных, если SecureConnection задан
        if self.secure_conn:
            data = self.secure_conn.encrypt(data)
        if self.protocol == 'tcp':
            # Отправка данных через TCP (потоковое соединение)
            assert self.writer is not None
            self.writer.write(data)
            # Ожидаем, пока данные будут отправлены (поддержка механизма backpressure)
            await self.writer.drain()
        elif self.protocol == 'udp':
            # Отправка данных через UDP (не требует установления соединения на уровне протокола)
            assert self.sock is not None
            loop = asyncio.get_running_loop()
            # sock_sendall отправляет данные через сокет; для UDP отправляется один пакет
            await loop.sock_sendall(self.sock, data)

    async def recv(self, n: int = 4096) -> bytes:
        """
        Асинхронно читает данные от удаленного узла.
        Полученные данные расшифровываются при необходимости (если задан secure_conn).
        Для TCP читает до n байт из StreamReader, для UDP получает один датаграм (до n байт).
        :param n: Максимальное количество байт для чтения.
        :return: Расшифрованные данные (bytes). Возвращает b'' если TCP-соединение закрыто.
        """
        if not self._connected:
            raise RuntimeError("Соединение не установлено")
        raw_data = b''
        if self.protocol == 'tcp':
            assert self.reader is not None
            # Читаем данные из TCP-потока (максимум n байт). Может вернуть меньше, либо b'' если соединение закрыто.
            raw_data = await self.reader.read(n)
            if raw_data == b'':
                # Пустые данные означают, что соединение закрыто на удаленной стороне.
                return b''
        elif self.protocol == 'udp':
            assert self.sock is not None
            loop = asyncio.get_running_loop()
            # Получаем один UDP-пакет (до n байт). Если пакет больше n, лишние данные будут отброшены.
            raw_data = await loop.sock_recv(self.sock, n)
            if raw_data == b'':
                # Пустой результат для UDP возможен только если сокет был закрыт с нашей стороны.
                return b''
        # Дешифрование данных, если SecureConnection задан.
        if self.secure_conn and raw_data:
            # Попытка расшифровать; при неудаче будет выброшено исключение.
            return self.secure_conn.decrypt(raw_data)
        return raw_data

    async def close(self):
        """
        Закрывает транспортное соединение.
        Для TCP закрывает поток и дожидается его закрытия, для UDP — закрывает сокет.
        """
        if not self._connected:
            return
        if self.protocol == 'tcp':
            assert self.writer is not None
            try:
                # Закрываем TCP-соединение
                self.writer.close()
                # Дожидаемся закрытия (метод wait_closed доступен начиная с Python 3.7)
                await self.writer.wait_closed()
            except Exception:
                pass
        elif self.protocol == 'udp':
            assert self.sock is not None
            try:
                # Закрываем UDP-сокет
                self.sock.close()
            except Exception:
                pass
        self._connected = False
        # При необходимости закрываем объект SecureConnection (например, для очистки секретных данных)
        if self.secure_conn and hasattr(self.secure_conn, 'close'):
            try:
                self.secure_conn.close()
            except Exception:
                pass
