import socket
import secrets
from utils.users import USERS  # словарь с данными пользователей: {login: {...}}

class Node:
    """
    Класс узла (пользователя) сети. При создании определяется текущий пользователь
    по локальному IP-адресу: ищется запись в USERS с совпадающим IP. Загружает RSA-ключи
    этого пользователя из config (USERS) и предоставляет атрибуты:
      - name: имя/логин пользователя
      - ip: локальный IP-адрес пользователя
      - rsa_pub: RSA открытый ключ пользователя
      - rsa_priv: RSA закрытый ключ пользователя
      - inbox: список входящих сообщений (каждый элемент – кортеж (sender_name, message))
    Также генерируется пара ключей Diffie-Hellman:
      - dh_key: публичное значение DH этого узла (отправляется другим узлам для расчета секрета)
    Методы:
      - dh_set_peer(peer_public): вычисляет общий секретный ключ по публичному ключу другого узла (DH),
        сохраняет его в атрибуте shared_key и возвращает.
      - send_message(other_node, message): отправляет сообщение другому узлу (имитация),
        добавляя его во входящие сообщения получателя (other_node.inbox).
    """
    # Параметры для Diffie-Hellman (2048-битная группа MODP из RFC 3526, генератор g=2)
    P = int(
        "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16
    )
    G = 2

    def __init__(self):
        # Определяем локальный IP-адрес текущей машины
        try:
            # Создаем UDP-сокет и выполняем подключение для получения своего IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
        except Exception:
            # Fallback: если не удалось через сокет, пробуем через hostname
            local_ip = socket.gethostbyname(socket.gethostname())
        finally:
            try:
                sock.close()
            except Exception:
                pass

        # Ищем пользователя с таким IP в конфигурации USERS
        user_info = None
        user_name = None
        for login, info in USERS.items():
            if info.get("ip") == local_ip:
                user_info = info
                user_name = login
                break
        if user_info is None:
            raise RuntimeError(f"IP-адрес {local_ip} не найден в конфигурации пользователей.")

        # Устанавливаем атрибуты пользователя
        self.name = user_info.get("login", user_name)
        self.ip = local_ip
        self.rsa_priv = user_info["rsa_priv"]
        self.rsa_pub = user_info["rsa_pub"]

        # Генерируем DH ключи для этого узла
        # Случайный приватный ключ в диапазоне [2, P-2]
        self._dh_private = secrets.randbelow(Node.P - 3) + 2
        # Публичный DH-ключ (открытое значение) для обмена
        self.dh_key = pow(Node.G, self._dh_private, Node.P)

        # Инициализируем "почтовый ящик" для входящих сообщений
        self.inbox = []
        # Атрибут для хранения общего секрета после вычисления DH
        self.shared_key = None

    def dh_set_peer(self, peer_public):
        """
        Вычисляет общий Diffie-Hellman ключ (shared secret) на основе публичного
        ключа другого узла `peer_public`. Результат (целое число) сохраняется в
        атрибут self.shared_key и также возвращается функцией.
        """
        # Приводим peer_public к целому числу, если он передан в виде строки или байтов
        if isinstance(peer_public, str):
            peer_public = int(peer_public)
        elif isinstance(peer_public, bytes):
            peer_public = int.from_bytes(peer_public, byteorder='big')
        # Вычисляем общий секрет: peer_public^self._dh_private mod P
        self.shared_key = pow(peer_public, self._dh_private, Node.P)
        return self.shared_key

    def send_message(self, other_node, message):
        """
        Отправляет сообщение другому узлу `other_node` – добавляет сообщение
        в его входящие сообщения. Сообщение сохраняется как кортеж
        (`self.name`, `message`) в списке other_node.inbox.
        """
        other_node.inbox.append((self.name, message))