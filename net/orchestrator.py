import base64
import json
import secrets
import socket
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # (при необходимости для симм. шифрования)
from utils.users import USERS

log = logging.getLogger("p2p.handshake")

class Orchestrator:
    def __init__(self, current_user: dict, context=None):
        """
        Orchestrator координирует многоэтапный handshake P2P-VPN.
        Работает с данными словаря текущего пользователя (login, neighbors, ip, ключи и пр.).
        """
        self.user = current_user  # словарь текущего пользователя
        self.context = context    # KDContext (для входящего соединения) или None
        self.network_thread = None
        # Инициализация RSA-ключей для всех узлов (если ещё не выполнена)
        self._ensure_keys()
        # Структуры состояния handshake
        self.seen_handshakes = set()      # уже обработанные handshake_id (для промежуточных узлов)
        self.route_back = {}             # маршрут для ответов: handshake_id -> откуда пришел запрос
        self.ephemeral_states = {}       # временные данные по активным handshake
        self.completed_handshakes = set()# завершённые handshake

    def _ensure_keys(self):
        """Генерирует/загружает RSA-ключи для всех пользователей (если не заданы)."""
        for uname, info in USERS.items():
            # Если приватный ключ уже есть как объект, используем его
            if isinstance(info.get("rsa_priv"), rsa.RSAPrivateKey):
                continue
            # Если есть приватный ключ в PEM-формате, загружаем его
            if info.get("rsa_priv"):
                try:
                    priv = serialization.load_pem_private_key(
                        info["rsa_priv"].encode() if isinstance(info["rsa_priv"], str) else info["rsa_priv"],
                        password=None, backend=default_backend()
                    )
                    info["rsa_priv"] = priv
                    info["rsa_pub"] = priv.public_key()
                    continue
                except Exception as e:
                    log.warning(f"Could not load RSA key for {uname}: {e}")
            # Генерируем новую пару ключей RSA
            priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            pub_key = priv_key.public_key()
            # Сохраняем объекты ключей в словаре пользователя
            info["rsa_priv"] = priv_key
            info["rsa_pub"] = pub_key
            # Сохраняем PEM-формат в словарь (необязательно, для отладки)
            info["rsa_priv_pem"] = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            info["rsa_pub_pem"] = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

    def set_network_thread(self, net_thread):
        """Устанавливает ссылку на сетевой поток (NetworkThread) для взаимодействия (если требуется)."""
        self.network_thread = net_thread

    def initiate_handshake(self, target_user: str) -> bool:
        """
        Инициатор (A): начать многоэтапный handshake для установления туннеля с узлом target_user (B).
        Возвращает True, если процесс инициирован.
        """
        # Проверяем наличие соседей
        neighbors = self.user.get("neighbors", [])
        if not neighbors or target_user not in neighbors:
            log.error(f"{self.user['login']}: Целевой узел {target_user} недоступен или не является соседом")
            return False

        # Генерируем идентификатор handshake-сессии
        handshake_id = secrets.token_hex(8)
        initiator_id = self.user["login"]
        # Подготовка хранения состояния handshake
        self.ephemeral_states[handshake_id] = {"role": "initiator", "target": target_user}
        log.info(f"Initiator {initiator_id}: starting handshake with {target_user} (handshake_id={handshake_id})")

        # Открываем сокет к узлу-назначению (B)
        target_ip = USERS.get(target_user, {}).get("ip")
        if not target_ip:
            log.error(f"Не найден IP адрес для пользователя {target_user}")
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target_ip, 5000))
        except Exception as e:
            log.error(f"{initiator_id}: Не удалось подключиться к {target_user} ({target_ip}): {e}")
            return False

        # Отправляем свой логин первой строкой, чтобы удалённый NetworkThread получил наш ID
        try:
            sock.sendall((initiator_id + "\n").encode())
        except Exception as e:
            log.error(f"{initiator_id}: Ошибка при отправке идентификатора: {e}")
            sock.close()
            return False

        # Создаем контекст соединения для отслеживания
        from net.kdcontext import KDContext
        conn_context = KDContext(target_user, sock)
        # Сгенерировать DH параметры (p, g, Ya) для главы 1
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        priv_key = parameters.generate_private_key()
        Ya = priv_key.public_key().public_numbers().y
        p = parameters.parameter_numbers().p
        g = parameters.parameter_numbers().g
        # Сохраняем приватный DH-ключ
        self.ephemeral_states[handshake_id]["dh_priv"] = priv_key
        self.ephemeral_states[handshake_id]["dh_params"] = parameters
        # Формируем payload главы 1: DH параметры (p, g, Ya) и случайный nonce
        payload = {
            "DH": {"p": p, "g": g, "Y": Ya},
            "nonce": secrets.token_hex(16)
        }
        payload_bytes = json.dumps(payload).encode()

        # Шифруем payload открытым RSA ключом целевого узла
        target_pub: rsa.RSAPublicKey = USERS[target_user].get("rsa_pub")
        if not target_pub:
            log.error(f"{initiator_id}: Неизвестен открытый ключ RSA пользователя {target_user}")
            sock.close()
            return False
        rsa_chunks = []
        # Максимальный размер блока для RSA-OAEP шифрования
        max_len = target_pub.key_size // 8 - 66
        for i in range(0, len(payload_bytes), max_len):
            chunk = payload_bytes[i:i + max_len]
            enc_chunk = target_pub.encrypt(chunk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            rsa_chunks.append(base64.b64encode(enc_chunk).decode())
        # Формируем и отправляем сообщение handshake (stage 1)
        msg_out = {
            "type": "handshake",
            "id": handshake_id,
            "initiator": initiator_id,
            "target": target_user,
            "stage": 1,
            "chunks": rsa_chunks
        }
        try:
            conn_context.socket.sendall((json.dumps(msg_out) + "\n").encode())
        except Exception as e:
            log.error(f"{initiator_id}: Ошибка отправки handshake-init: {e}")
            sock.close()
            return False

        # Запускаем поток для обработки оставшихся этапов handshake
        import threading
        thread = threading.Thread(target=self._initiator_handshake_thread, args=(handshake_id, conn_context), daemon=True)
        thread.start()
        return True

    def _initiator_handshake_thread(self, handshake_id: str, context):
        """Фоновый поток для продолжения handshake инициатором (A)."""
        initiator_id = self.user["login"]
        target_id = self.ephemeral_states[handshake_id]["target"]
        sock = context.socket
        try:
            # Ожидаем ответ этапа 1.5 (RSA-ответ с DH Y_target)
            response_line = self._recv_line(sock)
            if not response_line:
                log.error(f"Initiator {initiator_id}: нет ответа от {target_id} на этапе 1.5 (соединение закрыто)")
                sock.close()
                return
            try:
                msg = json.loads(response_line)
            except Exception as e:
                log.error(f"Initiator {initiator_id}: неверный формат ответа: {e}")
                sock.close()
                return
            stage = msg.get("stage")
            if stage != 1.5:
                log.error(f"Initiator {initiator_id}: неожидаемое сообщение (stage={stage}) вместо 1.5")
            # Обрабатываем ответ главы 1 (stage 1.5)
            self._handle_handshake_response(msg, from_id=target_id, handshake_id=handshake_id, context=context)
            # Отправляем сообщение Child-SA (stage 3)
            child_data = {
                "addr": initiator_id,
                "SA": {"key": secrets.token_hex(8)},  # пример данных Child-SA
                "I6": "set"
            }
            child_bytes = json.dumps(child_data).encode()
            # Шифруем child-SA открытым ключом B
            target_pub: rsa.RSAPublicKey = USERS[target_id]["rsa_pub"]
            env_chunks = []
            max_len = target_pub.key_size // 8 - 66
            for i in range(0, len(child_bytes), max_len):
                part = child_bytes[i:i + max_len]
                enc = target_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                env_chunks.append(enc.hex())
            msg_child = {
                "type": "handshake",
                "id": handshake_id,
                "initiator": initiator_id,
                "target": target_id,
                "stage": 3,
                "env_chunks_x2": env_chunks
            }
            sock.sendall((json.dumps(msg_child) + "\n").encode())
            log.info(f"Initiator {initiator_id}: sent Child-SA (stage 3) to {target_id}")

            # Ожидаем решения пользователя B (stage 9 или закрытие)
            response_line = self._recv_line(sock)
            if not response_line:
                log.warning(f"Initiator {initiator_id}: соединение закрыто до завершения handshake (вероятно, отклонено пользователем)")
                sock.close()
                return
            msg2 = json.loads(response_line)
            stage2 = msg2.get("stage")
            if stage2 != 9:
                log.error(f"Initiator {initiator_id}: ожидался stage 9, получено stage={stage2}")
            else:
                log.info(f"Initiator {initiator_id}: received acceptance (stage 9) from {target_id}")
            # При получении stage 9 от B – пользователь B принял соединение, выполняем финальный обмен DH (stage 12)
            # Генерируем финальные DH-параметры и ключ
            params_final = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            priv_final = params_final.generate_private_key()
            Y_final = priv_final.public_key().public_numbers().y
            p_final = params_final.parameter_numbers().p
            g_final = params_final.parameter_numbers().g
            # Сохраняем финальный приватный ключ для вычисления общего секрета
            self.ephemeral_states[handshake_id]["final_priv"] = priv_final
            dh_payload = {"p": p_final, "g": g_final, "Y": Y_final}
            dh_bytes = json.dumps(dh_payload).encode()
            # Шифруем DH-параметры открытым ключом B
            final_chunks = []
            max_len = target_pub.key_size // 8 - 66
            for i in range(0, len(dh_bytes), max_len):
                part = dh_bytes[i:i + max_len]
                enc = target_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                final_chunks.append(base64.b64encode(enc).decode())
            msg_final = {
                "type": "handshake",
                "id": handshake_id,
                "initiator": initiator_id,
                "target": target_id,
                "stage": 12,
                "chunks": final_chunks
            }
            sock.sendall((json.dumps(msg_final) + "\n").encode())
            log.info(f"Initiator {initiator_id}: sent final DH params (stage 12) to {target_id}")
            # Ожидаем ответ B (stage 12.5 с Yb)
            response_line = self._recv_line(sock)
            if not response_line:
                log.error(f"Initiator {initiator_id}: не получен ответ DH от {target_id} (соединение прервано)")
                sock.close()
                return
            msg3 = json.loads(response_line)
            # Обрабатываем ответ финального обмена (stage 12.5)
            self._handle_handshake_response(msg3, from_id=target_id, handshake_id=handshake_id, context=context)
            # Закрываем соединение (туннель установлен, дальнейший обмен шифруется на более высоком уровне)
            sock.close()
            log.info(f"Initiator {initiator_id}: handshake {handshake_id} complete. Tunnel to {target_id} established.")
        except Exception as e:
            log.error(f"Initiator {initiator_id}: ошибка в процессе handshake: {e}", exc_info=True)
            try:
                sock.close()
            except Exception:
                pass

    def continue_handshake(self):
        """
        Продолжение handshake на стороне принимающего (B) после согласия пользователя.
        Выполняет финальные шаги обмена ключами (главы 9–12) и устанавливает соединение.
        """
        if not self.context:
            return  # применимо только для принимающей стороны с установленным контекстом
        remote_id = self.context.remote_id  # Инициатор (A)
        # Получаем handshake_id текущей сессии (предполагаем, что ранее сохранён)
        handshake_id = getattr(self.context, "handshake_id", None)
        if not handshake_id or handshake_id not in self.ephemeral_states:
            log.warning(f"{self.user['login']}: Unknown handshake_id, cannot continue handshake")
            handshake_id = list(self.ephemeral_states.keys())[0] if self.ephemeral_states else None
        log.info(f"Target {self.user['login']}: user accepted connection from {remote_id}, finalizing handshake...")
        try:
            # Формируем и отправляем подтверждение (stage 9) инициатору
            resp_data = {"SA": f"{self.user['login']}-{remote_id}"}
            resp_bytes = json.dumps(resp_data).encode()
            initiator_pub: rsa.RSAPublicKey = USERS[remote_id].get("rsa_pub")
            rsa_chunks = []
            max_len = initiator_pub.key_size // 8 - 66
            for i in range(0, len(resp_bytes), max_len):
                part = resp_bytes[i:i + max_len]
                enc = initiator_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                rsa_chunks.append(base64.b64encode(enc).decode())
            msg_resp = {
                "type": "handshake",
                "id": handshake_id,
                "initiator": remote_id,
                "target": self.user["login"],
                "stage": 9,
                "chunks": rsa_chunks
            }
            self.context.socket.sendall((json.dumps(msg_resp) + "\n").encode())
            # Ожидаем финального DH-запроса (stage 12) от инициатора
            data_line = self._recv_line(self.context.socket)
            if not data_line:
                log.error(f"Target {self.user['login']}: инициатор {remote_id} прервал соединение до завершения")
                self.context.socket.close()
                return
            msg_final = json.loads(data_line)
            # Обрабатываем прямой DH-обмен (stage 12)
            self._handle_handshake_request(msg_final, from_id=remote_id, handshake_id=handshake_id)
            # Отправляем ответ с Yb (stage 12.5)
            if handshake_id in self.ephemeral_states:
                Yb = self.ephemeral_states[handshake_id].get("Yb")
            else:
                Yb = None
            if Yb is None:
                log.error(f"Target {self.user['login']}: отсутствует Yb для handshake {handshake_id}")
                self.context.socket.close()
                return
            Yb_payload = json.dumps({"Y": Yb}).encode()
            initiator_pub = USERS[remote_id]["rsa_pub"]
            chunks_out = []
            max_len = initiator_pub.key_size // 8 - 66
            for i in range(0, len(Yb_payload), max_len):
                part = Yb_payload[i:i + max_len]
                enc = initiator_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                chunks_out.append(base64.b64encode(enc).decode())
            msg_final_resp = {
                "type": "handshake",
                "id": handshake_id,
                "initiator": remote_id,
                "target": self.user["login"],
                "stage": 12.5,
                "chunks": chunks_out
            }
            self.context.socket.sendall((json.dumps(msg_final_resp) + "\n").encode())
            # Завершаем handshake
            shared_key = self.ephemeral_states[handshake_id].get("shared_key_final")
            try:
                self.context.socket.close()
            except Exception:
                pass
            log.info(f"Target {self.user['login']}: handshake {handshake_id} complete. Tunnel {remote_id}-{self.user['login']} established.")
            # Здесь можно вызывать callback on_handshake_complete, передавая shared_key
        except Exception as e:
            log.error(f"Target {self.user['login']}: ошибка при завершении handshake: {e}", exc_info=True)
            try:
                self.context.socket.close()
            except Exception:
                pass

    def abort(self):
        """Прервать текущий процесс handshake."""
        # Если есть активный сокет (входящий или исходящий), закрываем его
        try:
            if self.context:
                self.context.socket.close()
        except Exception:
            pass
        log.info(f"{self.user['login']}: handshake aborted/cancelled.")

    def on_message(self, msg: dict, from_id: str):
        """
        Обработчик входящих handshake-сообщений (для режима маршрутизации через соседей).
        """
        if msg.get("type") != "handshake":
            return
        stage = msg.get("stage")
        handshake_id = msg.get("id")
        # Вызов соответствующих обработчиков в зависимости от этапа
        if stage in (1, 3, 12):
            self._handle_handshake_request(msg, from_id, handshake_id=handshake_id)
        elif stage in (1.5, 9, 12.5):
            self._handle_handshake_response(msg, from_id, handshake_id=handshake_id)
        # Иные этапы (напр., 2, 5.2, 1.6) в данной реализации не обрабатываются явно

    def _handle_handshake_request(self, msg: dict, from_id: str, handshake_id: str = None, context=None):
        """Обработка входящего запроса handshake (на конечном узле B или промежуточном узле)."""
        stage = msg.get("stage")
        # Обработка начального RSA-конверта (stage 1) на целевом узле B
        if stage == 1 and from_id is not None:
            # Расшифровываем DH-параметры инициатора своим приватным ключом RSA
            enc_chunks = msg.get("chunks", [])
            full_data = b""
            for chunk_b64 in enc_chunks:
                enc_chunk = base64.b64decode(chunk_b64.encode())
                part = self.user["rsa_priv"].decrypt(enc_chunk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                full_data += part
            payload = json.loads(full_data.decode())
            # Извлекаем DH параметры инициатора
            p = payload["DH"]["p"]
            g = payload["DH"]["g"]
            Ya = payload["DH"]["Y"]
            # Генерируем свой DH-ключ (Yb)
            params = dh.DHParameterNumbers(p, g).parameters(default_backend())
            priv_b = params.generate_private_key()
            Yb = priv_b.public_key().public_numbers().y
            # Вычисляем общий секрет (shared_secret) с инициатором
            shared_secret = priv_b.exchange(dh.DHPublicNumbers(Ya, dh.DHParameterNumbers(p, g)).public_key(default_backend()))
            # Сохраняем состояние handshake
            hid = handshake_id or secrets.token_hex(8)
            self.ephemeral_states[hid] = {"priv_b": priv_b, "shared_secret": shared_secret}
            if self.context:
                # Привязываем handshake_id к контексту (для дальнейшего использования)
                self.context.handshake_id = hid
            # Формируем и отправляем ответ (stage 1.5) с Yb
            resp_payload = {"DH": {"Y": Yb}}
            resp_bytes = json.dumps(resp_payload).encode()
            # Шифруем ответ открытым ключом RSA отправителя (A)
            initiator_pub: rsa.RSAPublicKey = USERS[from_id]["rsa_pub"]
            enc_resp = initiator_pub.encrypt(resp_bytes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            resp_msg = {
                "type": "handshake",
                "id": hid,
                "initiator": from_id,
                "target": self.user["login"],
                "stage": 1.5,
                "blob": base64.b64encode(enc_resp).decode()
            }
            # Отправляем обратно отправителю (через socket контекста)
            if self.context:
                self.context.socket.sendall((json.dumps(resp_msg) + "\n").encode())
            log.info(f"Target {self.user['login']}: responded with DH-Yb (stage 1.5) to initiator {from_id}")
        # Обработка сообщения с Child-SA от инициатора (stage 3) на целевом узле B
        elif stage == 3:
            chunks_hex = msg.get("env_chunks_x2", [])
            if not chunks_hex:
                return
            # Расшифровываем RSA-конверт приватным ключом B
            full_bytes = b""
            for hex_chunk in chunks_hex:
                enc_chunk = bytes.fromhex(hex_chunk)
                part = self.user["rsa_priv"].decrypt(enc_chunk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                full_bytes += part
            data = json.loads(full_bytes.decode())
            child_sa = data.get("SA")
            log.info(f"Target {self.user['login']}: received Child-SA from {msg.get('initiator')}: {child_sa}")
            # Сохраняем полученные данные (можно использовать при формировании ответа)
            if handshake_id:
                self.ephemeral_states.setdefault(handshake_id, {})["child_sa_in"] = child_sa
        # Обработка прямого DH-запроса (stage 12) на целевом узле B
        elif stage == 12:
            chunks = msg.get("chunks", [])
            if not chunks:
                return
            full = b""
            for ch in chunks:
                enc = base64.b64decode(ch.encode())
                part = self.user["rsa_priv"].decrypt(enc, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                full += part
            dh_params = json.loads(full.decode())
            p = dh_params["p"]
            g = dh_params["g"]
            Ya = dh_params["Y"]
            # Генерируем свой DH ключ для финального обмена
            params = dh.DHParameterNumbers(p, g).parameters(default_backend())
            priv_final = params.generate_private_key()
            Yb = priv_final.public_key().public_numbers().y
            shared_AB = priv_final.exchange(dh.DHPublicNumbers(Ya, dh.DHParameterNumbers(p, g)).public_key(default_backend()))
            # Вычисляем окончательный общий ключ (hash от shared_AB)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(shared_AB)
            key_bytes = digest.finalize()
            if handshake_id:
                self.ephemeral_states.setdefault(handshake_id, {})["Yb"] = Yb
                self.ephemeral_states[handshake_id]["shared_key_final"] = key_bytes
            log.info(f"Target {self.user['login']}: computed final shared key for handshake {handshake_id}")
        # Промежуточные узлы (X*) могут обрабатывать другие стадии (не реализовано полностью)

    def _handle_handshake_response(self, msg: dict, from_id: str, handshake_id: str = None, context=None):
        """Обработка входящего ответа handshake (на узле-инициаторе A или промежуточном узле)."""
        stage = msg.get("stage")
        # Обработка RSA-ответа (stage 1.5) на узле-инициаторе A
        if stage == 1.5 and "blob" in msg:
            blob_b64 = msg.get("blob")
            if not blob_b64:
                return
            # Расшифровываем своим RSA-приватным ключом
            enc_data = base64.b64decode(blob_b64.encode())
            try:
                resp_bytes = self.user["rsa_priv"].decrypt(enc_data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            except Exception as e:
                log.error(f"{self.user['login']}: Failed to decrypt RSA response: {e}")
                return
            resp = json.loads(resp_bytes.decode())
            Yb = resp.get("DH", {}).get("Y")
            if Yb is None or not handshake_id or handshake_id not in self.ephemeral_states:
                return
            # Завершаем вычисление общего секрета по DH (KD1)
            priv_a: dh.DHPrivateKey = self.ephemeral_states[handshake_id]["dh_priv"]
            params: dh.DHParameters = self.ephemeral_states[handshake_id]["dh_params"]
            shared = priv_a.exchange(dh.DHPublicNumbers(Yb, params.parameter_numbers()).public_key(default_backend()))
            # Сохраняем полученный секрет (или его хеш)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(shared)
            kd1 = digest.finalize()
            self.ephemeral_states[handshake_id]["shared_secret"] = kd1
            log.info(f"Initiator {self.user['login']}: DH shared secret established with {from_id}")
        # Обработка ответа с Child-SA от цели (stage 9) на узле-инициаторе A
        elif stage == 9:
            chunks_b64 = msg.get("chunks", [])
            if not chunks_b64:
                return
            full = b""
            for ch in chunks_b64:
                enc = base64.b64decode(ch.encode())
                part = self.user["rsa_priv"].decrypt(enc, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                full += part
            data = json.loads(full.decode())
            child_sa_resp = data.get("SA")
            log.info(f"Initiator {self.user['login']}: received Child-SA response from {from_id}: {child_sa_resp}")
            # (Дополнительно можно сохранить или использовать child_sa_resp)
        # Обработка финального ответа DH (stage 12.5) на узле-инициаторе A
        elif stage == 12.5:
            chunks = msg.get("chunks", [])
            if not chunks or not handshake_id or handshake_id not in self.ephemeral_states:
                return
            full_bytes = b""
            for ch in chunks:
                enc = base64.b64decode(ch.encode())
                part = self.user["rsa_priv"].decrypt(enc, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                full_bytes += part
            resp = json.loads(full_bytes.decode())
            Yb = resp.get("Y")
            priv_final: dh.DHPrivateKey = self.ephemeral_states[handshake_id].get("final_priv")
            if Yb is None or priv_final is None:
                return
            # Вычисляем общий финальный секрет и итоговый ключ
            shared_final = priv_final.exchange(dh.DHPublicNumbers(Yb, priv_final.public_key().public_numbers().parameter_numbers).public_key(default_backend()))
            digest = hashes.Hash(hashes.SHA256())
            digest.update(shared_final)
            key_bytes = digest.finalize()
            log.info(f"Initiator {self.user['login']}: final shared key established for handshake {handshake_id}")
            # Завершаем handshake
            self.completed_handshakes.add(handshake_id)
            if handshake_id in self.ephemeral_states:
                self.ephemeral_states.pop(handshake_id, None)
        # Промежуточные узлы могли бы обрабатывать иные стадии (не реализовано)

    def feed_initial_data(self, data: bytes):
        """Получение избыточных данных, прочитанных до передачи управления Orchestrator (например, из NetworkThread)."""
        # Сохраняем начальные данные, чтобы обработать их в run_responder_initial
        self._initial_data = data

    def _recv_line(self, sock: socket.socket) -> str:
        """Вспомогательная функция: прочитать одну строку (до \n) из сокета."""
        buffer = b""
        try:
            while b"\n" not in buffer:
                chunk = sock.recv(4096)
                if not chunk:
                    return ""  # соединение закрыто
                buffer += chunk
                if len(buffer) > 8192:  # ограничение на размер строки
                    break
        except Exception as e:
            return ""
        # Разделяем по первой новой строке
        if b"\n" in buffer:
            line, rest = buffer.split(b"\n", 1)
        else:
            line, rest = buffer, b""
        # Если есть лишние данные после первой строки, сохраняем их для дальнейшей обработки
        if rest and hasattr(self, "_initial_data_buffer"):
            self._initial_data_buffer += rest
        else:
            self._initial_data_buffer = rest
        return line.decode(errors="ignore").strip()

    def run_responder_initial(self):
        """
        Выполнение начальных этапов handshake (главы 1–8) на принимающем узле (B) до подтверждения пользователя.
        """
        if not self.context:
            return
        sock = self.context.socket
        # Если были предварительно полученные данные от NetworkThread, обрабатываем их сначала
        if hasattr(self, "_initial_data") and self._initial_data:
            buffer = self._initial_data
        else:
            buffer = b""
        try:
            # Читаем данные до получения хотя бы одной полной строки (handshake сообщения)
            sock.settimeout(10.0)
            while b"\n" not in buffer:
                chunk = sock.recv(4096)
                if not chunk:
                    return  # соединение закрыто
                buffer += chunk
                if len(buffer) > 8192:
                    break
        except Exception as e:
            log.error(f"{self.user['login']}: Error reading handshake init: {e}")
            return
        # Выделяем первую строку JSON
        if b"\n" in buffer:
            line_bytes, remaining = buffer.split(b"\n", 1)
        else:
            line_bytes, remaining = buffer, b""
        try:
            msg = json.loads(line_bytes.decode(errors="ignore").strip())
        except Exception as e:
            log.error(f"{self.user['login']}: Received malformed handshake message: {e}")
            return
        stage = msg.get("stage")
        handshake_id = msg.get("id") or secrets.token_hex(8)
        # Сохраняем оставшиеся данные, если есть, для последующей обработки (например, stage 3)
        self._pending_data = remaining
        # Обрабатываем входящее handshake-сообщение (ожидается stage 1)
        if stage == 1:
            initiator_id = msg.get("initiator")
            self._handle_handshake_request(msg, from_id=initiator_id, handshake_id=handshake_id)
        else:
            log.error(f"{self.user['login']}: Unexpected handshake stage {stage} in initial request")
            return
        # После ответа stage 1.5, ожидаем сообщение stage 3 (Child-SA) от инициатора
        try:
            if self._pending_data and b"\n" in self._pending_data:
                line_bytes, remaining = self._pending_data.split(b"\n", 1)
                self._pending_data = remaining
            else:
                # Блокирующее чтение следующей строки
                line_bytes = b""
                if self._pending_data:
                    # если была часть данных, начинаем с неё
                    buffer2 = self._pending_data
                    self._pending_data = b""
                else:
                    buffer2 = b""
                while b"\n" not in buffer2:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer2 += chunk
                    if len(buffer2) > 8192:
                        break
                if b"\n" in buffer2:
                    line_bytes, remaining = buffer2.split(b"\n", 1)
                    self._pending_data = remaining
                else:
                    line_bytes = buffer2
            if line_bytes:
                msg2 = json.loads(line_bytes.decode(errors="ignore").strip())
                if msg2.get("stage") == 3:
                    initiator_id = msg2.get("initiator")
                    self._handle_handshake_request(msg2, from_id=initiator_id, handshake_id=handshake_id)
        except Exception as e:
            log.error(f"{self.user['login']}: Error processing stage 3: {e}", exc_info=True)
```python

# orchestrator.py
```python
import base64
import json
import secrets
import socket
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # (при необходимости для симм. шифрования)
from utils.users import USERS

log = logging.getLogger("p2p.handshake")

class Orchestrator:
    def __init__(self, current_user: dict, context=None):
        """
        Orchestrator координирует многоэтапный handshake P2P-VPN.
        Работает с данными словаря текущего пользователя (login, neighbors, ip, ключи и пр.).
        """
        self.user = current_user  # словарь текущего пользователя
        self.context = context    # KDContext (для входящего соединения) или None
        self.network_thread = None
        # Инициализация RSA-ключей для всех узлов (если ещё не выполнена)
        self._ensure_keys()
        # Структуры состояния handshake
        self.seen_handshakes = set()      # уже обработанные handshake_id (для промежуточных узлов)
        self.route_back = {}             # маршрут для ответов: handshake_id -> откуда пришел запрос
        self.ephemeral_states = {}       # временные данные по активным handshake
        self.completed_handshakes = set()# завершённые handshake

    def _ensure_keys(self):
        """Генерирует/загружает RSA-ключи для всех пользователей (если не заданы)."""
        for uname, info in USERS.items():
            # Если приватный ключ уже есть как объект, используем его
            if isinstance(info.get("rsa_priv"), rsa.RSAPrivateKey):
                continue
            # Если есть приватный ключ в PEM-формате, загружаем его
            if info.get("rsa_priv"):
                try:
                    priv = serialization.load_pem_private_key(
                        info["rsa_priv"].encode() if isinstance(info["rsa_priv"], str) else info["rsa_priv"],
                        password=None, backend=default_backend()
                    )
                    info["rsa_priv"] = priv
                    info["rsa_pub"] = priv.public_key()
                    continue
                except Exception as e:
                    log.warning(f"Could not load RSA key for {uname}: {e}")
            # Генерируем новую пару ключей RSA
            priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            pub_key = priv_key.public_key()
            # Сохраняем объекты ключей в словаре пользователя
            info["rsa_priv"] = priv_key
            info["rsa_pub"] = pub_key
            # Сохраняем PEM-формат в словарь (необязательно, для отладки)
            info["rsa_priv_pem"] = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            info["rsa_pub_pem"] = pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

    def set_network_thread(self, net_thread):
        """Устанавливает ссылку на сетевой поток (NetworkThread) для взаимодействия (если требуется)."""
        self.network_thread = net_thread

    def initiate_handshake(self, target_user: str) -> bool:
        """
        Инициатор (A): начать многоэтапный handshake для установления туннеля с узлом target_user (B).
        Возвращает True, если процесс инициирован.
        """
        # Проверяем наличие соседей
        neighbors = self.user.get("neighbors", [])
        if not neighbors or target_user not in neighbors:
            log.error(f"{self.user['login']}: Целевой узел {target_user} недоступен или не является соседом")
            return False

        # Генерируем идентификатор handshake-сессии
        handshake_id = secrets.token_hex(8)
        initiator_id = self.user["login"]
        # Подготовка хранения состояния handshake
        self.ephemeral_states[handshake_id] = {"role": "initiator", "target": target_user}
        log.info(f"Initiator {initiator_id}: starting handshake with {target_user} (handshake_id={handshake_id})")

        # Открываем сокет к узлу-назначению (B)
        target_ip = USERS.get(target_user, {}).get("ip")
        if not target_ip:
            log.error(f"Не найден IP адрес для пользователя {target_user}")
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((target_ip, 5000))
        except Exception as e:
            log.error(f"{initiator_id}: Не удалось подключиться к {target_user} ({target_ip}): {e}")
            return False

        # Отправляем свой логин первой строкой, чтобы удалённый NetworkThread получил наш ID
        try:
            sock.sendall((initiator_id + "\n").encode())
        except Exception as e:
            log.error(f"{initiator_id}: Ошибка при отправке идентификатора: {e}")
            sock.close()
            return False

        # Создаем контекст соединения для отслеживания
        from net.kdcontext import KDContext
        conn_context = KDContext(target_user, sock)
        # Сгенерировать DH параметры (p, g, Ya) для главы 1
        parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
        priv_key = parameters.generate_private_key()
        Ya = priv_key.public_key().public_numbers().y
        p = parameters.parameter_numbers().p
        g = parameters.parameter_numbers().g
        # Сохраняем приватный DH-ключ
        self.ephemeral_states[handshake_id]["dh_priv"] = priv_key
        self.ephemeral_states[handshake_id]["dh_params"] = parameters
        # Формируем payload главы 1: DH параметры (p, g, Ya) и случайный nonce
        payload = {
            "DH": {"p": p, "g": g, "Y": Ya},
            "nonce": secrets.token_hex(16)
        }
        payload_bytes = json.dumps(payload).encode()

        # Шифруем payload открытым RSA ключом целевого узла
        target_pub: rsa.RSAPublicKey = USERS[target_user].get("rsa_pub")
        if not target_pub:
            log.error(f"{initiator_id}: Неизвестен открытый ключ RSA пользователя {target_user}")
            sock.close()
            return False
        rsa_chunks = []
        # Максимальный размер блока для RSA-OAEP шифрования
        max_len = target_pub.key_size // 8 - 66
        for i in range(0, len(payload_bytes), max_len):
            chunk = payload_bytes[i:i + max_len]
            enc_chunk = target_pub.encrypt(chunk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            rsa_chunks.append(base64.b64encode(enc_chunk).decode())
        # Формируем и отправляем сообщение handshake (stage 1)
        msg_out = {
            "type": "handshake",
            "id": handshake_id,
            "initiator": initiator_id,
            "target": target_user,
            "stage": 1,
            "chunks": rsa_chunks
        }
        try:
            conn_context.socket.sendall((json.dumps(msg_out) + "\n").encode())
        except Exception as e:
            log.error(f"{initiator_id}: Ошибка отправки handshake-init: {e}")
            sock.close()
            return False

        # Запускаем поток для обработки оставшихся этапов handshake
        import threading
        thread = threading.Thread(target=self._initiator_handshake_thread, args=(handshake_id, conn_context), daemon=True)
        thread.start()
        return True

    def _initiator_handshake_thread(self, handshake_id: str, context):
        """Фоновый поток для продолжения handshake инициатором (A)."""
        initiator_id = self.user["login"]
        target_id = self.ephemeral_states[handshake_id]["target"]
        sock = context.socket
        try:
            # Ожидаем ответ этапа 1.5 (RSA-ответ с DH Y_target)
            response_line = self._recv_line(sock)
            if not response_line:
                log.error(f"Initiator {initiator_id}: нет ответа от {target_id} на этапе 1.5 (соединение закрыто)")
                sock.close()
                return
            try:
                msg = json.loads(response_line)
            except Exception as e:
                log.error(f"Initiator {initiator_id}: неверный формат ответа: {e}")
                sock.close()
                return
            stage = msg.get("stage")
            if stage != 1.5:
                log.error(f"Initiator {initiator_id}: неожидаемое сообщение (stage={stage}) вместо 1.5")
            # Обрабатываем ответ главы 1 (stage 1.5)
            self._handle_handshake_response(msg, from_id=target_id, handshake_id=handshake_id, context=context)
            # Отправляем сообщение Child-SA (stage 3)
            child_data = {
                "addr": initiator_id,
                "SA": {"key": secrets.token_hex(8)},  # пример данных Child-SA
                "I6": "set"
            }
            child_bytes = json.dumps(child_data).encode()
            # Шифруем child-SA открытым ключом B
            target_pub: rsa.RSAPublicKey = USERS[target_id]["rsa_pub"]
            env_chunks = []
            max_len = target_pub.key_size // 8 - 66
            for i in range(0, len(child_bytes), max_len):
                part = child_bytes[i:i + max_len]
                enc = target_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                env_chunks.append(enc.hex())
            msg_child = {
                "type": "handshake",
                "id": handshake_id,
                "initiator": initiator_id,
                "target": target_id,
                "stage": 3,
                "env_chunks_x2": env_chunks
            }
            sock.sendall((json.dumps(msg_child) + "\n").encode())
            log.info(f"Initiator {initiator_id}: sent Child-SA (stage 3) to {target_id}")

            # Ожидаем решения пользователя B (stage 9 или закрытие)
            response_line = self._recv_line(sock)
            if not response_line:
                log.warning(f"Initiator {initiator_id}: соединение закрыто до завершения handshake (вероятно, отклонено пользователем)")
                sock.close()
                return
            msg2 = json.loads(response_line)
            stage2 = msg2.get("stage")
            if stage2 != 9:
                log.error(f"Initiator {initiator_id}: ожидался stage 9, получено stage={stage2}")
            else:
                log.info(f"Initiator {initiator_id}: received acceptance (stage 9) from {target_id}")
            # При получении stage 9 от B – пользователь B принял соединение, выполняем финальный обмен DH (stage 12)
            # Генерируем финальные DH-параметры и ключ
            params_final = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            priv_final = params_final.generate_private_key()
            Y_final = priv_final.public_key().public_numbers().y
            p_final = params_final.parameter_numbers().p
            g_final = params_final.parameter_numbers().g
            # Сохраняем финальный приватный ключ для вычисления общего секрета
            self.ephemeral_states[handshake_id]["final_priv"] = priv_final
            dh_payload = {"p": p_final, "g": g_final, "Y": Y_final}
            dh_bytes = json.dumps(dh_payload).encode()
            # Шифруем DH-параметры открытым ключом B
            final_chunks = []
            max_len = target_pub.key_size // 8 - 66
            for i in range(0, len(dh_bytes), max_len):
                part = dh_bytes[i:i + max_len]
                enc = target_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                final_chunks.append(base64.b64encode(enc).decode())
            msg_final = {
                "type": "handshake",
                "id": handshake_id,
                "initiator": initiator_id,
                "target": target_id,
                "stage": 12,
                "chunks": final_chunks
            }
            sock.sendall((json.dumps(msg_final) + "\n").encode())
            log.info(f"Initiator {initiator_id}: sent final DH params (stage 12) to {target_id}")
            # Ожидаем ответ B (stage 12.5 с Yb)
            response_line = self._recv_line(sock)
            if not response_line:
                log.error(f"Initiator {initiator_id}: не получен ответ DH от {target_id} (соединение прервано)")
                sock.close()
                return
            msg3 = json.loads(response_line)
            # Обрабатываем ответ финального обмена (stage 12.5)
            self._handle_handshake_response(msg3, from_id=target_id, handshake_id=handshake_id, context=context)
            # Закрываем соединение (туннель установлен, дальнейший обмен шифруется на более высоком уровне)
            sock.close()
            log.info(f"Initiator {initiator_id}: handshake {handshake_id} complete. Tunnel to {target_id} established.")
        except Exception as e:
            log.error(f"Initiator {initiator_id}: ошибка в процессе handshake: {e}", exc_info=True)
            try:
                sock.close()
            except Exception:
                pass

    def continue_handshake(self):
        """
        Продолжение handshake на стороне принимающего (B) после согласия пользователя.
        Выполняет финальные шаги обмена ключами (главы 9–12) и устанавливает соединение.
        """
        if not self.context:
            return  # применимо только для принимающей стороны с установленным контекстом
        remote_id = self.context.remote_id  # Инициатор (A)
        # Получаем handshake_id текущей сессии (предполагаем, что ранее сохранён)
        handshake_id = getattr(self.context, "handshake_id", None)
        if not handshake_id or handshake_id not in self.ephemeral_states:
            log.warning(f"{self.user['login']}: Unknown handshake_id, cannot continue handshake")
            handshake_id = list(self.ephemeral_states.keys())[0] if self.ephemeral_states else None
        log.info(f"Target {self.user['login']}: user accepted connection from {remote_id}, finalizing handshake...")
        try:
            # Формируем и отправляем подтверждение (stage 9) инициатору
            resp_data = {"SA": f"{self.user['login']}-{remote_id}"}
            resp_bytes = json.dumps(resp_data).encode()
            initiator_pub: rsa.RSAPublicKey = USERS[remote_id].get("rsa_pub")
            rsa_chunks = []
            max_len = initiator_pub.key_size // 8 - 66
            for i in range(0, len(resp_bytes), max_len):
                part = resp_bytes[i:i + max_len]
                enc = initiator_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                rsa_chunks.append(base64.b64encode(enc).decode())
            msg_resp = {
                "type": "handshake",
                "id": handshake_id,
                "initiator": remote_id,
                "target": self.user["login"],
                "stage": 9,
                "chunks": rsa_chunks
            }
            self.context.socket.sendall((json.dumps(msg_resp) + "\n").encode())
            # Ожидаем финального DH-запроса (stage 12) от инициатора
            data_line = self._recv_line(self.context.socket)
            if not data_line:
                log.error(f"Target {self.user['login']}: инициатор {remote_id} прервал соединение до завершения")
                self.context.socket.close()
                return
            msg_final = json.loads(data_line)
            # Обрабатываем прямой DH-обмен (stage 12)
            self._handle_handshake_request(msg_final, from_id=remote_id, handshake_id=handshake_id)
            # Отправляем ответ с Yb (stage 12.5)
            if handshake_id in self.ephemeral_states:
                Yb = self.ephemeral_states[handshake_id].get("Yb")
            else:
                Yb = None
            if Yb is None:
                log.error(f"Target {self.user['login']}: отсутствует Yb для handshake {handshake_id}")
                self.context.socket.close()
                return
            Yb_payload = json.dumps({"Y": Yb}).encode()
            initiator_pub = USERS[remote_id]["rsa_pub"]
            chunks_out = []
            max_len = initiator_pub.key_size // 8 - 66
            for i in range(0, len(Yb_payload), max_len):
                part = Yb_payload[i:i + max_len]
                enc = initiator_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                chunks_out.append(base64.b64encode(enc).decode())
            msg_final_resp = {
                "type": "handshake",
                "id": handshake_id,
                "initiator": remote_id,
                "target": self.user["login"],
                "stage": 12.5,
                "chunks": chunks_out
            }
            self.context.socket.sendall((json.dumps(msg_final_resp) + "\n").encode())
            # Завершаем handshake
            shared_key = self.ephemeral_states[handshake_id].get("shared_key_final")
            try:
                self.context.socket.close()
            except Exception:
                pass
            log.info(f"Target {self.user['login']}: handshake {handshake_id} complete. Tunnel {remote_id}-{self.user['login']} established.")
            # Здесь можно вызывать callback on_handshake_complete, передавая shared_key
        except Exception as e:
            log.error(f"Target {self.user['login']}: ошибка при завершении handshake: {e}", exc_info=True)
            try:
                self.context.socket.close()
            except Exception:
                pass

    def abort(self):
        """Прервать текущий процесс handshake."""
        # Если есть активный сокет (входящий или исходящий), закрываем его
        try:
            if self.context:
                self.context.socket.close()
        except Exception:
            pass
        log.info(f"{self.user['login']}: handshake aborted/cancelled.")

    def on_message(self, msg: dict, from_id: str):
        """
        Обработчик входящих handshake-сообщений (для режима маршрутизации через соседей).
        """
        if msg.get("type") != "handshake":
            return
        stage = msg.get("stage")
        handshake_id = msg.get("id")
        # Вызов соответствующих обработчиков в зависимости от этапа
        if stage in (1, 3, 12):
            self._handle_handshake_request(msg, from_id, handshake_id=handshake_id)
        elif stage in (1.5, 9, 12.5):
            self._handle_handshake_response(msg, from_id, handshake_id=handshake_id)
        # Иные этапы (напр., 2, 5.2, 1.6) в данной реализации не обрабатываются явно

    def _handle_handshake_request(self, msg: dict, from_id: str, handshake_id: str = None, context=None):
        """Обработка входящего запроса handshake (на конечном узле B или промежуточном узле)."""
        stage = msg.get("stage")
        # Обработка начального RSA-конверта (stage 1) на целевом узле B
        if stage == 1 and from_id is not None:
            # Расшифровываем DH-параметры инициатора своим приватным ключом RSA
            enc_chunks = msg.get("chunks", [])
            full_data = b""
            for chunk_b64 in enc_chunks:
                enc_chunk = base64.b64decode(chunk_b64.encode())
                part = self.user["rsa_priv"].decrypt(enc_chunk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                full_data += part
            payload = json.loads(full_data.decode())
            # Извлекаем DH параметры инициатора
            p = payload["DH"]["p"]
            g = payload["DH"]["g"]
            Ya = payload["DH"]["Y"]
            # Генерируем свой DH-ключ (Yb)
            params = dh.DHParameterNumbers(p, g).parameters(default_backend())
            priv_b = params.generate_private_key()
            Yb = priv_b.public_key().public_numbers().y
            # Вычисляем общий секрет (shared_secret) с инициатором
            shared_secret = priv_b.exchange(dh.DHPublicNumbers(Ya, dh.DHParameterNumbers(p, g)).public_key(default_backend()))
            # Сохраняем состояние handshake
            hid = handshake_id or secrets.token_hex(8)
            self.ephemeral_states[hid] = {"priv_b": priv_b, "shared_secret": shared_secret}
            if self.context:
                # Привязываем handshake_id к контексту (для дальнейшего использования)
                self.context.handshake_id = hid
            # Формируем и отправляем ответ (stage 1.5) с Yb
            resp_payload = {"DH": {"Y": Yb}}
            resp_bytes = json.dumps(resp_payload).encode()
            # Шифруем ответ открытым ключом RSA отправителя (A)
            initiator_pub: rsa.RSAPublicKey = USERS[from_id]["rsa_pub"]
            enc_resp = initiator_pub.encrypt(resp_bytes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            resp_msg = {
                "type": "handshake",
                "id": hid,
                "initiator": from_id,
                "target": self.user["login"],
                "stage": 1.5,
                "blob": base64.b64encode(enc_resp).decode()
            }
            # Отправляем обратно отправителю (через socket контекста)
            if self.context:
                self.context.socket.sendall((json.dumps(resp_msg) + "\n").encode())
            log.info(f"Target {self.user['login']}: responded with DH-Yb (stage 1.5) to initiator {from_id}")
        # Обработка сообщения с Child-SA от инициатора (stage 3) на целевом узле B
        elif stage == 3:
            chunks_hex = msg.get("env_chunks_x2", [])
            if not chunks_hex:
                return
            # Расшифровываем RSA-конверт приватным ключом B
            full_bytes = b""
            for hex_chunk in chunks_hex:
                enc_chunk = bytes.fromhex(hex_chunk)
                part = self.user["rsa_priv"].decrypt(enc_chunk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                full_bytes += part
            data = json.loads(full_bytes.decode())
            child_sa = data.get("SA")
            log.info(f"Target {self.user['login']}: received Child-SA from {msg.get('initiator')}: {child_sa}")
            # Сохраняем полученные данные (можно использовать при формировании ответа)
            if handshake_id:
                self.ephemeral_states.setdefault(handshake_id, {})["child_sa_in"] = child_sa
        # Обработка прямого DH-запроса (stage 12) на целевом узле B
        elif stage == 12:
            chunks = msg.get("chunks", [])
            if not chunks:
                return
            full = b""
            for ch in chunks:
                enc = base64.b64decode(ch.encode())
                part = self.user["rsa_priv"].decrypt(enc, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                full += part
            dh_params = json.loads(full.decode())
            p = dh_params["p"]
            g = dh_params["g"]
            Ya = dh_params["Y"]
            # Генерируем свой DH ключ для финального обмена
            params = dh.DHParameterNumbers(p, g).parameters(default_backend())
            priv_final = params.generate_private_key()
            Yb = priv_final.public_key().public_numbers().y
            shared_AB = priv_final.exchange(dh.DHPublicNumbers(Ya, dh.DHParameterNumbers(p, g)).public_key(default_backend()))
            # Вычисляем окончательный общий ключ (hash от shared_AB)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(shared_AB)
            key_bytes = digest.finalize()
            if handshake_id:
                self.ephemeral_states.setdefault(handshake_id, {})["Yb"] = Yb
                self.ephemeral_states[handshake_id]["shared_key_final"] = key_bytes
            log.info(f"Target {self.user['login']}: computed final shared key for handshake {handshake_id}")
        # Промежуточные узлы (X*) могут обрабатывать другие стадии (не реализовано полностью)

    def _handle_handshake_response(self, msg: dict, from_id: str, handshake_id: str = None, context=None):
        """Обработка входящего ответа handshake (на узле-инициаторе A или промежуточном узле)."""
        stage = msg.get("stage")
        # Обработка RSA-ответа (stage 1.5) на узле-инициаторе A
        if stage == 1.5 and "blob" in msg:
            blob_b64 = msg.get("blob")
            if not blob_b64:
                return
            # Расшифровываем своим RSA-приватным ключом
            enc_data = base64.b64decode(blob_b64.encode())
            try:
                resp_bytes = self.user["rsa_priv"].decrypt(enc_data, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            except Exception as e:
                log.error(f"{self.user['login']}: Failed to decrypt RSA response: {e}")
                return
            resp = json.loads(resp_bytes.decode())
            Yb = resp.get("DH", {}).get("Y")
            if Yb is None or not handshake_id or handshake_id not in self.ephemeral_states:
                return
            # Завершаем вычисление общего секрета по DH (KD1)
            priv_a: dh.DHPrivateKey = self.ephemeral_states[handshake_id]["dh_priv"]
            params: dh.DHParameters = self.ephemeral_states[handshake_id]["dh_params"]
            shared = priv_a.exchange(dh.DHPublicNumbers(Yb, params.parameter_numbers()).public_key(default_backend()))
            # Сохраняем полученный секрет (или его хеш)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(shared)
            kd1 = digest.finalize()
            self.ephemeral_states[handshake_id]["shared_secret"] = kd1
            log.info(f"Initiator {self.user['login']}: DH shared secret established with {from_id}")
        # Обработка ответа с Child-SA от цели (stage 9) на узле-инициаторе A
        elif stage == 9:
            chunks_b64 = msg.get("chunks", [])
            if not chunks_b64:
                return
            full = b""
            for ch in chunks_b64:
                enc = base64.b64decode(ch.encode())
                part = self.user["rsa_priv"].decrypt(enc, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                full += part
            data = json.loads(full.decode())
            child_sa_resp = data.get("SA")
            log.info(f"Initiator {self.user['login']}: received Child-SA response from {from_id}: {child_sa_resp}")
            # (Дополнительно можно сохранить или использовать child_sa_resp)
        # Обработка финального ответа DH (stage 12.5) на узле-инициаторе A
        elif stage == 12.5:
            chunks = msg.get("chunks", [])
            if not chunks or not handshake_id or handshake_id not in self.ephemeral_states:
                return
            full_bytes = b""
            for ch in chunks:
                enc = base64.b64decode(ch.encode())
                part = self.user["rsa_priv"].decrypt(enc, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                full_bytes += part
            resp = json.loads(full_bytes.decode())
            Yb = resp.get("Y")
            priv_final: dh.DHPrivateKey = self.ephemeral_states[handshake_id].get("final_priv")
            if Yb is None or priv_final is None:
                return
            # Вычисляем общий финальный секрет и итоговый ключ
            shared_final = priv_final.exchange(dh.DHPublicNumbers(Yb, priv_final.public_key().public_numbers().parameter_numbers).public_key(default_backend()))
            digest = hashes.Hash(hashes.SHA256())
            digest.update(shared_final)
            key_bytes = digest.finalize()
            log.info(f"Initiator {self.user['login']}: final shared key established for handshake {handshake_id}")
            # Завершаем handshake
            self.completed_handshakes.add(handshake_id)
            if handshake_id in self.ephemeral_states:
                self.ephemeral_states.pop(handshake_id, None)
        # Промежуточные узлы могли бы обрабатывать иные стадии (не реализовано)

    def feed_initial_data(self, data: bytes):
        """Получение избыточных данных, прочитанных до передачи управления Orchestrator (например, из NetworkThread)."""
        # Сохраняем начальные данные, чтобы обработать их в run_responder_initial
        self._initial_data = data

    def _recv_line(self, sock: socket.socket) -> str:
        """Вспомогательная функция: прочитать одну строку (до \n) из сокета."""
        buffer = b""
        try:
            while b"\n" not in buffer:
                chunk = sock.recv(4096)
                if not chunk:
                    return ""  # соединение закрыто
                buffer += chunk
                if len(buffer) > 8192:  # ограничение на размер строки
                    break
        except Exception:
            return ""
        # Разделяем по первой новой строке
        if b"\n" in buffer:
            line, rest = buffer.split(b"\n", 1)
        else:
            line, rest = buffer, b""
        # Если есть лишние данные после первой строки, сохраняем их для дальнейшей обработки
        if rest and hasattr(self, "_initial_data_buffer"):
            self._initial_data_buffer += rest
        else:
            self._initial_data_buffer = rest
        return line.decode(errors="ignore").strip()

    def run_responder_initial(self):
        """
        Выполнение начальных этапов handshake (главы 1–8) на принимающем узле (B) до подтверждения пользователя.
        """
        if not self.context:
            return
        sock = self.context.socket
        # Если были предварительно полученные данные от NetworkThread, обрабатываем их сначала
        if hasattr(self, "_initial_data") and self._initial_data:
            buffer = self._initial_data
        else:
            buffer = b""
        try:
            # Читаем данные до получения хотя бы одной полной строки (handshake сообщения)
            sock.settimeout(10.0)
            while b"\n" not in buffer:
                chunk = sock.recv(4096)
                if not chunk:
                    return  # соединение закрыто
                buffer += chunk
                if len(buffer) > 8192:
                    break
        except Exception as e:
            log.error(f"{self.user['login']}: Error reading handshake init: {e}")
            return
        # Выделяем первую строку JSON
        if b"\n" in buffer:
            line_bytes, remaining = buffer.split(b"\n", 1)
        else:
            line_bytes, remaining = buffer, b""
        try:
            msg = json.loads(line_bytes.decode(errors="ignore").strip())
        except Exception as e:
            log.error(f"{self.user['login']}: Received malformed handshake message: {e}")
            return
        stage = msg.get("stage")
        handshake_id = msg.get("id") or secrets.token_hex(8)
        # Сохраняем оставшиеся данные, если есть, для последующей обработки (например, stage 3)
        self._pending_data = remaining
        # Обрабатываем входящее handshake-сообщение (ожидается stage 1)
        if stage == 1:
            initiator_id = msg.get("initiator")
            self._handle_handshake_request(msg, from_id=initiator_id, handshake_id=handshake_id)
        else:
            log.error(f"{self.user['login']}: Unexpected handshake stage {stage} in initial request")
            return
        # После ответа stage 1.5, ожидаем сообщение stage 3 (Child-SA) от инициатора
        try:
            if self._pending_data and b"\n" in self._pending_data:
                line_bytes, remaining = self._pending_data.split(b"\n", 1)
                self._pending_data = remaining
            else:
                # Блокирующее чтение следующей строки
                line_bytes = b""
                if self._pending_data:
                    # если была часть данных, начинаем с неё
                    buffer2 = self._pending_data
                    self._pending_data = b""
                else:
                    buffer2 = b""
                while b"\n" not in buffer2:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer2 += chunk
                    if len(buffer2) > 8192:
                        break
                if b"\n" in buffer2:
                    line_bytes, remaining = buffer2.split(b"\n", 1)
                    self._pending_data = remaining
                else:
                    line_bytes = buffer2
            if line_bytes:
                msg2 = json.loads(line_bytes.decode(errors="ignore").strip())
                if msg2.get("stage") == 3:
                    initiator_id = msg2.get("initiator")
                    self._handle_handshake_request(msg2, from_id=initiator_id, handshake_id=handshake_id)
        except Exception as e:
            log.error(f"{self.user['login']}: Error processing stage 3: {e}", exc_info=True)