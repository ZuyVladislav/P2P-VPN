import base64
import secrets
from cryptography.hazmat.primitives.asymmetric import x25519

class Orchestrator:
    def __init__(self, node):
        """
        Orchestrator отвечает за координацию многоэтапного handshake в P2P-VPN сети.
        Решает проблемы:
        - В протоколе участвуют все узлы (узлы могут пересылать handshake запросы друг другу).
        - Handshake выполняется по нескольким путям одновременно и завершается по наиболее успешному (первому полученному).
        - Обмен ключами происходит по сети (посредством сообщений), а не только через логи.
        """
        self.node = node
        # Множество уже обработанных handshake-запросов (чтобы не пересылать повторно и избегать петель).
        self.seen_handshakes = set()
        # Таблица маршрутизации ответов: handshake_id -> сосед, от которого пришел запрос (путь к инициатору).
        self.route_back = {}
        # Временное хранилище ключей и состояния для активных handshake по их ID.
        # Содержит приватные ключи инициатора или цели, вычисленные shared secret и пр.
        self.ephemeral_states = {}
        # Множество успешно завершённых handshake (для игнорирования дубликатов поздних ответов).
        self.completed_handshakes = set()

    def initiate_handshake(self, target_id):
        """
        Инициатор: начать процедуру handshake для установления туннеля с узлом target_id.
        Отправляет handshake-запрос по всем доступным соседям (многопутевой запрос).
        """
        # Сгенерировать уникальный ID handshake (например, 64-битный случайный идентификатор в hex-формате).
        handshake_id = secrets.token_hex(8)
        # Сгенерировать эпhemerный ключ инициатора (для обмена ключами Diffie-Hellman).
        initiator_priv = x25519.X25519PrivateKey.generate()
        initiator_pub = initiator_priv.public_key()
        initiator_pub_bytes = initiator_pub.public_bytes()  # байтовое представление публичного ключа
        # Сохранить состояние инициатора: его приватный ключ и целевой узел, для использования при получении ответа.
        self.ephemeral_states[handshake_id] = {
            "role": "initiator",
            "priv": initiator_priv,
            "target_id": target_id
        }
        # Сформировать сообщение handshake-запроса, содержащее публичный ключ инициатора.
        msg = {
            "type": "handshake_req",
            "id": handshake_id,
            "initiator": self.node.id,
            "target": target_id,
            "pub": base64.b64encode(initiator_pub_bytes).decode()  # кодируем публичный ключ инициатора (Base64)
        }
        # Пометить этот handshake_id как уже отправленный (чтобы собственный запрос не обработать как петлю).
        self.seen_handshakes.add(handshake_id)
        # Отправить запрос всем соседям узла (одновременно по разным путям).
        for neighbor_id in self.node.neighbors:
            # Отправляем handshake-запрос соседу. Предполагается, что self.node.send умеет отправлять сообщение указанному соседу.
            self.node.send(neighbor_id, msg)
        # (Дальнейшая обработка продолжится асинхронно при получении ответных сообщений.)

    def on_message(self, msg, from_id):
        """
        Обработчик входящих сетевых сообщений handshake. Вызывается, когда узел получает handshake-сообщение.
        """
        mtype = msg.get("type")
        if mtype == "handshake_req":
            self._handle_handshake_request(msg, from_id)
        elif mtype == "handshake_resp":
            self._handle_handshake_response(msg, from_id)
        # Игнорируем прочие типы сообщений (если такие есть).

    def _handle_handshake_request(self, msg, from_id):
        """
        Обработка входящего запроса на установление соединения (handshake request).
        Если узел является целью запроса, он формирует ответ.
        Если узел является промежуточным, пересылает запрос дальше всем соседям (кроме того, от кого получили).
        """
        handshake_id = msg["id"]
        initiator_id = msg["initiator"]
        target_id = msg["target"]
        # 1. Если текущий узел является целевым адресатом handshake:
        if target_id == self.node.id:
            # Проверяем, не обрабатывался ли уже этот handshake ранее (по другому пути).
            if handshake_id not in self.ephemeral_states:
                # Первый раз получаем этот handshake запрос: генерируем эпhemerный ключ для ответа.
                target_priv = x25519.X25519PrivateKey.generate()
                target_pub = target_priv.public_key()
                target_pub_bytes = target_pub.public_bytes()
                # Извлекаем публичный ключ инициатора из запроса и вычисляем общий секрет (shared secret) по алгоритму Diffie-Hellman.
                try:
                    initiator_pub_bytes = base64.b64decode(msg["pub"].encode())
                    initiator_pub = x25519.X25519PublicKey.from_public_bytes(initiator_pub_bytes)
                except Exception as e:
                    # Некорректные данные ключа инициатора
                    return  # просто игнорируем этот запрос, если не удалось распознать ключ
                shared_secret = target_priv.exchange(initiator_pub)
                # Сохраняем состояние handshake для цели: свой приватный ключ и вычисленный shared secret.
                # (Shared secret может понадобиться для установки шифрования, как только handshake завершится.)
                self.ephemeral_states[handshake_id] = {
                    "role": "target",
                    "priv": target_priv,
                    "initiator_id": initiator_id,
                    "secret": shared_secret
                }
            else:
                # Повторный handshake запрос с тем же ID (пришёл другим маршрутом).
                # Уже имеется сгенерированный приватный ключ и shared secret для этого handshake.
                # Будем повторно отправлять ответ с тем же публичным ключом (чтобы инициатор получил дубликат, если первый потерялся).
                target_priv = self.ephemeral_states[handshake_id]["priv"]
                target_pub_bytes = target_priv.public_key().public_bytes()
                # (shared_secret уже вычислен и сохранён, повторно вычислять не нужно.)
            # Формируем сообщение handshake-ответа, включаем публичный ключ узла-цели.
            resp_msg = {
                "type": "handshake_resp",
                "id": handshake_id,
                "initiator": initiator_id,
                "target": self.node.id,
                "pub": base64.b64encode(target_pub_bytes).decode()
            }
            # Отправляем ответ тому соседу, от которого получили запрос (то есть обратно по маршруту к инициатору).
            self.node.send(from_id, resp_msg)
            # **Примечание:** На стороне цели handshake считается выполненным после отправки ответа.
            # Узел-цель получил общий секрет (shared_secret) и может ждать подтверждения или сразу использовать его для шифрования входящего трафика.
            # В данной реализации подтверждение от инициатора не предусмотрено, предполагается, что туннель устанавливается,
            # а при получении первого зашифрованного пакета от инициатора станет ясно, что handshake успешно завершён.

        # 2. Если текущий узел является промежуточным (не инициатор и не цель):
        elif initiator_id != self.node.id:
            # Проверяем, не видели ли мы уже этот handshake_id (чтобы не пересылать дубликаты по сети и не создавать циклы).
            if handshake_id in self.seen_handshakes:
                # Уже пересылали этот запрос ранее, игнорируем повтор.
                return
            # Помечаем данный handshake как виденный на этом узле.
            self.seen_handshakes.add(handshake_id)
            # Запоминаем, от какого соседа пришел запрос (чтобы знать, куда отправлять ответ обратно к инициатору).
            self.route_back[handshake_id] = from_id
            # Пересылаем handshake-запрос дальше: всем соседям, кроме того, от кого получили.
            for neighbor_id in self.node.neighbors:
                if neighbor_id == from_id:
                    continue  # не отправляем обратно тому же узлу, от которого получили
                self.node.send(neighbor_id, msg)
            # Узел-промежуточный не участвует в вычислении ключей, он лишь транзит для handshake.

        # 3. Если текущий узел сам является инициатором (не должно происходить,
        # так как мы помечаем свой запрос и не пересылаем его себе, но на всякий случай):
        else:
            # Игнорируем собственный запрос, если по какой-то причине он вернулся (например, при сложной топологии с циклами).
            return

    def _handle_handshake_response(self, msg, from_id):
        """
        Обработка входящего ответа на handshake (handshake response).
        Если узел - инициатор данного handshake, то вычисляется общий секрет и соединение завершается.
        Если узел - промежуточный, то ответ пересылается дальше по маршруту к инициатору.
        """
        handshake_id = msg["id"]
        initiator_id = msg["initiator"]
        target_id = msg["target"]
        # 1. Если текущий узел является инициатором этого handshake (ждём ответ):
        if initiator_id == self.node.id:
            # Проверяем, не завершили ли мы уже этот handshake (например, уже получили один ответ по другому пути).
            if handshake_id in self.completed_handshakes:
                # Уже получили более быстрый ответ и установили соединение, этот дубликат игнорируем.
                return
            # Достаём сохранённое состояние инициатора (приватный ключ) по handshake_id.
            if handshake_id not in self.ephemeral_states:
                # Нет состояния для данного handshake (неожиданная ситуация).
                return  # игнорируем, так как мы не инициировали этот handshake или уже удалили состояние.
            initiator_priv = self.ephemeral_states[handshake_id]["priv"]
            # Извлекаем публичный ключ ответившего узла (целевого) из сообщения.
            try:
                responder_pub_bytes = base64.b64decode(msg["pub"].encode())
                responder_pub = x25519.X25519PublicKey.from_public_bytes(responder_pub_bytes)
            except Exception as e:
                # Некорректные данные публичного ключа в ответе, не удаётся вычислить секрет.
                return
            # Вычисляем общий секрет (shared secret) с помощью своего приватного ключа инициатора и публичного ключа узла-цели.
            shared_secret = initiator_priv.exchange(responder_pub)
            # Помечаем handshake как успешно завершённый.
            self.completed_handshakes.add(handshake_id)
            # Удаляем больше не нужное состояние инициатора для этого handshake.
            del self.ephemeral_states[handshake_id]
            # Уведомляем верхний уровень (узел) о завершении handshake и готовности зашифрованного туннеля.
            # Предполагается, что у объекта node есть метод для обработки успешного соединения.
            if hasattr(self.node, "on_handshake_complete"):
                self.node.on_handshake_complete(target_id, shared_secret)
            # Теперь узел-инициатор и узел-цель имеют общий секрет shared_secret,
            # который можно использовать для шифрования VPN-трафика между ними.
            # Дополнительные шаги: настроить шифрование канала, обменяться подтверждениями, если требуется.

        # 2. Если текущий узел является промежуточным узлом на пути ответа:
        elif target_id != self.node.id:
            # Для промежуточного узла: пересылаем ответ дальше к инициатору по ранее сохранённому маршруту.
            if handshake_id not in self.route_back:
                # Не нашли маршрут до инициатора для этого handshake (возможно, истек срок действия или не сохраняли), игнорируем.
                return
            # Определяем следующего соседа на пути к инициатору (откуда изначально пришёл запрос).
            next_hop = self.route_back[handshake_id]
            # Пересылаем handshake-ответ дальше.
            self.node.send(next_hop, msg)
            # Примечание: Не удаляем сразу запись route_back,
            # т.к. по сети мог прийти ещё один ответ по другому пути.
            # Запись может быть удалена по таймеру или после полной установки соединения.

        # 3. Если текущий узел вдруг получает handshake_resp будучи целевым узлом:
        else:
            # В данной реализации двустадийного handshake (request/response) узел-цель не ожидает получать handshake_resp.
            # (Handshake_resp предназначен только инициатору, поэтому этот случай исключительный.)
            return