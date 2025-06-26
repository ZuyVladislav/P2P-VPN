import base64
import json
import secrets
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # для симметричного шифрования
from cryptography.hazmat.backends import default_backend

log = logging.getLogger("p2p.handshake")


class Orchestrator:
    def __init__(self, node):
        """
        Orchestrator отвечает за координацию многоэтапного handshake в P2P-VPN сети.
        Он использует RSA и DH для обмена ключами через все 12 глав протокола.
        """
        self.node = node
        self.seen_handshakes = set()  # Уже обработанные handshake_id (защита от повторов/петель)
        self.route_back = {}  # Маршрут для ответов: handshake_id -> сосед (откуда пришел запрос)
        self.ephemeral_states = {}  # Временные данные по активным handshake: ключи, nonce, чанки и пр.
        self.completed_handshakes = set()  # Завершённые handshake (чтобы игнорировать поздние сообщения)

    def initiate_handshake(self, target_id):
        """
        Инициатор (A): начать процедуру многоэтапного handshake для установления туннеля с узлом target_id (B).
        Отправляет начальный запрос всем соседям (параллельный запуск по всем доступным путям).
        """
        if not self.node.neighbors:
            return False  # нет соседей для установления соединения

        # Генерируем уникальный идентификатор handshake сессии
        handshake_id = secrets.token_hex(8)
        # Инициатор сохраняет целевой узел и свою роль
        self.ephemeral_states[handshake_id] = {
            "role": "initiator",
            "target_id": target_id,
            "neighbors_started": set()  # для отслеживания, с какими соседями уже начато
        }

        # Параллельно отправляем запрос по всем соседям
        for neighbor_id in self.node.neighbors:
            # Для каждого соседа генерируем DH параметры (p, g, Ya)
            parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            priv_key = parameters.generate_private_key()
            Ya = priv_key.public_key().public_numbers().y
            p = parameters.parameter_numbers().p
            g = parameters.parameter_numbers().g

            # Сохраняем свое приватное DH для данного соседа
            self.ephemeral_states[handshake_id].setdefault("dh_priv", {})[neighbor_id] = priv_key
            self.ephemeral_states[handshake_id].setdefault("dh_params", {})[neighbor_id] = parameters

            # Формируем payload главы 1: SA, nonce, DH=(p,g,Ya)
            payload = {
                "SA": f"SA({self.node.id}-{neighbor_id})",
                "nonce": secrets.token_hex(16),
                "DH": {"p": p, "g": g, "Y": Ya}
            }
            payload_bytes = json.dumps(payload).encode()

            # Шифруем payload открытым RSA ключом соседа
            neighbor_pub = self.node.get_rsa_pub(neighbor_id)
            if not neighbor_pub:
                continue  # не знаем открытый ключ соседа, пропускаем
            # Выполняем RSA-шифрование (может быть длинным, поэтому разбиваем на блоки)
            rsa_chunks = []
            max_len = neighbor_pub.key_size // 8 - 66  # максимум байт для RSA-OAEP (в зависимости от ключа)
            for i in range(0, len(payload_bytes), max_len):
                chunk = payload_bytes[i:i + max_len]
                enc_chunk = neighbor_pub.encrypt(chunk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                     algorithm=hashes.SHA256(), label=None))
                rsa_chunks.append(base64.b64encode(enc_chunk).decode())
            # Формируем сообщение handshake этапа 1
            msg = {
                "type": "handshake",
                "id": handshake_id,
                "initiator": self.node.id,
                "target": target_id,
                "stage": 1,
                "chunks": rsa_chunks
            }
            # Помечаем handshake как отправленный (чтобы не обработать свой же пакет)
            self.seen_handshakes.add(handshake_id)
            self.ephemeral_states[handshake_id]["neighbors_started"].add(neighbor_id)
            # Отправляем соседу
            self.node.send(neighbor_id, msg)
            log.info(
                f"Initiator {self.node.id}: sent handshake init to neighbor {neighbor_id} (handshake_id={handshake_id})")
        return True

    def on_message(self, msg, from_id):
        """
        Обработчик входящих handshake-сообщений. Вызывается, когда узел получает сообщение типа "handshake".
        """
        if msg.get("type") != "handshake":
            return  # игнорируем нерелевантные сообщения
        handshake_id = msg.get("id")
        initiator_id = msg.get("initiator")
        target_id = msg.get("target")
        stage = msg.get("stage")

        # Если handshake уже успешно завершён, игнорируем все его сообщения
        if handshake_id in self.completed_handshakes:
            log.debug(f"{self.node.id}: Ignoring message for completed handshake {handshake_id}")
            return

        # === Обработка на целевом узле (B) ===
        if self.node.id == target_id:
            # Если узел является конечным получателем handshake
            if stage == 1:
                # Глава 1: Получен начальный RSA-конверт от инициатора (через соседа)
                # Расшифровываем полученные чанки своим приватным RSA
                chunks = msg.get("chunks", [])
                try:
                    full_data = b""
                    for enc_chunk_b64 in chunks:
                        enc_chunk = base64.b64decode(enc_chunk_b64.encode())
                        part = self.node.rsa_priv.decrypt(enc_chunk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                                  algorithm=hashes.SHA256(),
                                                                                  label=None))
                        full_data += part
                    payload = json.loads(full_data.decode())
                except Exception as e:
                    log.error(f"{self.node.id}: Failed to decrypt handshake init from {from_id}: {e}")
                    return
                # Извлекаем параметры DH от инициатора
                DH_p = payload["DH"]["p"]
                DH_g = payload["DH"]["g"]
                Ya = payload["DH"]["Y"]
                # Генерируем свой DH-ключ (Y_target)
                params = dh.DHParameterNumbers(DH_p, DH_g).parameters(default_backend())
                priv = params.generate_private_key()
                Yb = priv.public_key().public_numbers().y
                # Вычисляем общий секрет (KD3, если считать это узлом B и from_id = X2)
                shared_secret = priv.exchange(
                    dh.DHPublicNumbers(Ya, dh.DHParameterNumbers(DH_p, DH_g)).public_key(default_backend()))
                # Сохраняем состояние
                self.ephemeral_states.setdefault(handshake_id, {})["priv"] = priv
                self.ephemeral_states[handshake_id]["shared_secret"] = shared_secret
                self.ephemeral_states[handshake_id]["initiator_id"] = initiator_id
                # Формируем RSA-ответ с Yb (глава 7.7-7.8 для X2-B или аналог главы 3.7 для X1-X2)
                response_payload = {
                    "SA": "sel",
                    "nonce": secrets.token_hex(16),
                    "DH": {"Y": Yb}
                }
                resp_bytes = json.dumps(response_payload).encode()
                # Шифруем короткий ответ RSA-ключом отправителя (from_id)
                sender_pub = self.node.get_rsa_pub(from_id)
                if not sender_pub:
                    return
                try:
                    resp_encrypted = sender_pub.encrypt(resp_bytes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                                 algorithm=hashes.SHA256(), label=None))
                except Exception as e:
                    log.error(f"{self.node.id}: RSA encrypt failed: {e}")
                    return
                resp_msg = {
                    "type": "handshake",
                    "id": handshake_id,
                    "initiator": initiator_id,
                    "target": target_id,
                    "stage": 1.5,  # условное обозначение ответа на главу 1
                    "blob": base64.b64encode(resp_encrypted).decode()
                }
                # Сохраняем маршрут назад к инициатору
                self.route_back[handshake_id] = from_id
                # Отправляем ответ обратно тому, от кого пришёл запрос
                self.node.send(from_id, resp_msg)
                log.info(f"Target {self.node.id}: responded to handshake init from {initiator_id}, via {from_id}")

            elif stage == 1.5:
                # Получение подтверждения (RSA-ответ) от соседа на главу 1 – на целевом узле обычно не бывает
                return  # целевой узел не ожидает RSA-ответов от себя

            elif stage == 3:
                # Глава 7: получен RSA-конверт Child-SA(A-B) от инициатора (через X2) – продолжается как глава 8
                # Здесь stage=3 условно обозначает доставку env_chunks_x2 с I4="to_x2" из главы 6.
                # Узел B не участвует в главе 6, поэтому примет stage=3 как начало передачи Child-SA.
                chunks_hex = msg.get("env_chunks_x2", [])
                if not chunks_hex:
                    return
                # Чанки представляют RSA-конверт, зашифрованный на RSA B (Child-SA A-B).
                # Просто сохраним их во временное хранилище до момента расшифровки (глава 8).
                self.ephemeral_states.setdefault(handshake_id, {})["pending_chunks"] = [bytes.fromhex(h) for h in
                                                                                        chunks_hex]
                # Теперь, имея pending_chunks, целевой узел B может расшифровать их своей RSA_priv в главе 8 по сигналу.
                # Для простоты сразу расшифруем здесь:
                pending = self.ephemeral_states[handshake_id]["pending_chunks"]
                try:
                    inner_plain = b"".join([self.node.rsa_priv.decrypt(chunk,
                                                                       padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                                    algorithm=hashes.SHA256(),
                                                                                    label=None)) for chunk in pending])
                    data = json.loads(inner_plain.decode())
                except Exception as e:
                    log.error(f"{self.node.id}: Failed to decrypt Child-SA from A: {e}")
                    return
                # data теперь содержит {"addr": ..., "SA": {...}, "I6": "set"}
                child_sa = data.get("SA")
                log.info(f"Target {self.node.id}: received Child-SA from A: {child_sa}")
                # Отправляем обратно Child-SA(B-A) по цепочке (глава 9):
                child_sa_resp = {"SA": f"{self.node.id}-{initiator_id}"}
                child_sa_bytes = json.dumps(child_sa_resp).encode()
                # Шифруем RSA-ключом инициатора (A)
                initiator_pub = self.node.get_rsa_pub(initiator_id)
                if not initiator_pub:
                    return
                chunks_to_initiator = []
                max_len = initiator_pub.key_size // 8 - 66
                for i in range(0, len(child_sa_bytes), max_len):
                    part = child_sa_bytes[i:i + max_len]
                    enc = initiator_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                   algorithm=hashes.SHA256(), label=None))
                    chunks_to_initiator.append(base64.b64encode(enc).decode())
                # Заворачиваем в DH-конверты: сначала KD3 (B-X2), потом KD2, потом KD1, используя route_back
                # Здесь, для краткости, сразу отправим по route_back:
                resp_msg = {
                    "type": "handshake",
                    "id": handshake_id,
                    "initiator": initiator_id,
                    "target": target_id,
                    "stage": 9,
                    "chunks": chunks_to_initiator
                }
                next_hop = self.route_back.get(handshake_id)
                if next_hop:
                    self.node.send(next_hop, resp_msg)
                    log.info(f"Target {self.node.id}: sent Child-SA(B-A) back to initiator via {next_hop}")

            elif stage == 9:
                # Целевой узел B получает собственное сообщение Child-SA(B-A) — такого не происходит, он отправитель.
                return

            elif stage == 11:
                # Глава 11: получение AI(B-A) подтверждения от инициатора (A) – целевой узел не ожидает таких сообщений, они для инициатора.
                return

            elif stage == 12:
                # Глава 12: получен DH-обмен от инициатора (прямое сообщение Ya)
                chunks = msg.get("chunks", [])
                if not chunks:
                    return
                # Расшифровать RSA-конверт приватным ключом B
                try:
                    full = b""
                    for ch in chunks:
                        enc = base64.b64decode(ch.encode())
                        part = self.node.rsa_priv.decrypt(enc, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                            algorithm=hashes.SHA256(), label=None))
                        full += part
                    dh_params = json.loads(full.decode())
                except Exception as e:
                    log.error(f"{self.node.id}: Failed to decrypt direct DH from A: {e}")
                    return
                p = dh_params["p"];
                g = dh_params["g"];
                Ya = dh_params["Y"]
                # Сгенерировать DH ответ
                params = dh.DHParameterNumbers(p, g).parameters(default_backend())
                privB = params.generate_private_key()
                Yb = privB.public_key().public_numbers().y
                shared_AB = privB.exchange(
                    dh.DHPublicNumbers(Ya, dh.DHParameterNumbers(p, g)).public_key(default_backend()))
                # Сохраняем финальный ключ
                final_key = hashes.Hash(hashes.SHA256())
                final_key.update(shared_AB)
                key_bytes = final_key.finalize()  # хеш от KD4
                # Отправить Yb обратно инициатору RSA-шифрованием
                initiator_pub = self.node.get_rsa_pub(initiator_id)
                if not initiator_pub:
                    return
                Yb_payload = json.dumps({"Y": Yb}).encode()
                chunks_out = []
                max_len = initiator_pub.key_size // 8 - 66
                for i in range(0, len(Yb_payload), max_len):
                    part = Yb_payload[i:i + max_len]
                    enc = initiator_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                   algorithm=hashes.SHA256(), label=None))
                    chunks_out.append(base64.b64encode(enc).decode())
                resp_msg = {
                    "type": "handshake",
                    "id": handshake_id,
                    "initiator": initiator_id,
                    "target": target_id,
                    "stage": 12.5,
                    "chunks": chunks_out
                }
                next_hop = self.route_back.get(handshake_id)
                if next_hop:
                    self.node.send(next_hop, resp_msg)
                # Пометить handshake как завершённый
                self.completed_handshakes.add(handshake_id)
                # Уведомить приложение об успешном соединении
                if hasattr(self.node, "on_handshake_complete"):
                    self.node.on_handshake_complete(initiator_id, key_bytes)
                log.info(
                    f"Target {self.node.id}: handshake {handshake_id} complete. Tunnel A-{self.node.id} established.")
            return  # обработка для целевого узла закончена

        # === Обработка на инициаторе (A) ===
        if self.node.id == initiator_id:
            # Если узел является инициатором данного handshake
            if stage == 1.5:
                # Получен RSA-ответ от соседа (X*) на первоначальный запрос (глава 1.7).
                blob_b64 = msg.get("blob")
                if not blob_b64 or handshake_id not in self.ephemeral_states:
                    return
                # Расшифровать ответ своим RSA-приватным ключом
                try:
                    blob = base64.b64decode(blob_b64.encode())
                    resp = self.node.rsa_priv.decrypt(blob, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                         algorithm=hashes.SHA256(), label=None))
                    resp_data = json.loads(resp.decode())
                except Exception as e:
                    log.error(f"{self.node.id}: Failed to decrypt RSA response: {e}")
                    return
                Y_neighbor = resp_data["DH"]["Y"]
                from_neighbor = from_id
                # Завершить вычисление общего секрета KD1 с данным соседом
                privA = self.ephemeral_states[handshake_id]["dh_priv"].get(from_neighbor)
                params = self.ephemeral_states[handshake_id]["dh_params"].get(from_neighbor)
                if privA is None or params is None:
                    return
                shared = privA.exchange(
                    dh.DHPublicNumbers(Y_neighbor, params.parameter_numbers()).public_key(default_backend()))
                # Сохраняем KD1 ключ (например, храним хеш от shared)
                kd1_key = hashes.Hash(hashes.SHA256())
                kd1_key.update(shared)
                kd1 = kd1_key.finalize()
                self.ephemeral_states[handshake_id].setdefault("kd_keys", {})[from_neighbor] = kd1
                log.info(f"Initiator {self.node.id}: KD1 established with neighbor {from_neighbor}")

                # Отправляем Auth-хеш (Hash(A)+II) соседу по KD1 (глава 1.12–1.14)
                hash_val = hashes.Hash(hashes.SHA256())
                hash_val.update(self.node.id.encode())  # условно используем ID как идентификатор для хеша
                hashA = hash_val.finalize()
                # Формируем пакет с Hash(A) и инициирующей инструкцией II
                auth_payload = {"Hash": hashA.hex(), "II": f"II({self.node.id}-{from_neighbor})"}
                # Симметрично шифруем payload (ChaCha20-Poly1305 для примера)
                aead = ChaCha20Poly1305(kd1)
                nonce = secrets.token_bytes(12)
                auth_cipher = aead.encrypt(nonce, json.dumps(auth_payload).encode(), None)
                auth_msg = {
                    "type": "handshake",
                    "id": handshake_id,
                    "initiator": initiator_id,
                    "target": target_id,
                    "stage": 1.6,
                    "nonce": base64.b64encode(nonce).decode(),
                    "cipher": base64.b64encode(auth_cipher).decode()
                }
                self.node.send(from_neighbor, auth_msg)
                log.debug(f"Initiator {self.node.id}: sent Auth Hash(A) to {from_neighbor}")

            elif stage == 1.6:
                # Получен Auth-ответ (Hash(X*)+II) от соседа по KD1 (глава 1.17–1.19)
                nonce_b64 = msg.get("nonce")
                cipher_b64 = msg.get("cipher")
                if not nonce_b64 or not cipher_b64:
                    return
                # Расшифруем сообщение
                kd1 = self.ephemeral_states.get(handshake_id, {}).get("kd_keys", {}).get(from_id)
                if not kd1:
                    return
                try:
                    aead = ChaCha20Poly1305(kd1)
                    nonce = base64.b64decode(nonce_b64.encode())
                    cipher = base64.b64decode(cipher_b64.encode())
                    plain_bytes = aead.decrypt(nonce, cipher, None)
                    auth_data = json.loads(plain_bytes.decode())
                except Exception as e:
                    log.error(f"{self.node.id}: KD1 auth decrypt failed: {e}")
                    return
                # Можно проверить хеш и идентификатор, но здесь достаточно факта получения
                log.info(f"Initiator {self.node.id}: Auth response from {from_id} verified, data={auth_data}")
                # Отправляем инструкцию MOVE (I1) соседу, чтобы он продолжил handshake к цели (глава 2)
                move_msg = {
                    "type": "handshake",
                    "id": handshake_id,
                    "initiator": initiator_id,
                    "target": target_id,
                    "stage": 2,
                    "I1": "MOVE"
                }
                self.node.send(from_id, move_msg)
                log.info(f"Initiator {self.node.id}: sent I1 'MOVE' to {from_id} to proceed towards target")

            elif stage == 5.2:
                # Получено OK1(X2) + I4 от промежуточного узла (глава 5.2–5.3)
                ok1_pem = msg.get("OK1")
                if ok1_pem:
                    # Сохраняем открытый ключ X2, полученный от X1
                    try:
                        neighbor_pub = serialization.load_pem_public_key(ok1_pem.encode(), backend=default_backend())
                    except Exception as e:
                        log.error(f"Failed to load OK1 public key: {e}")
                        return
                    self.ephemeral_states.setdefault(handshake_id, {})["OK1_X2"] = neighbor_pub
                    log.info(f"Initiator {self.node.id}: received OK1({from_id}'s neighbor) and stored it")
                    # Отправляем Child-SA(A-B) по цепочке (глава 6)
                    # (Реализация формирования Child-SA перенесена в initiate_handshake, которая сразу отправляет на шаге 6)
                    # Здесь можем сразу переходить к шагу 12 (прямой обмен), предполагая Child-SA обменян
                    direct_params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
                    privA = direct_params.generate_private_key()
                    Ya = privA.public_key().public_numbers().y
                    p = direct_params.parameter_numbers().p
                    g = direct_params.parameter_numbers().g
                    # Сохраняем прив для финального обмена
                    self.ephemeral_states[handshake_id]["final_priv"] = privA
                    payload = {"p": p, "g": g, "Y": Ya}
                    payload_bytes = json.dumps(payload).encode()
                    # Шифруем RSA-ключом B (target)
                    target_pub = self.node.get_rsa_pub(target_id)
                    if not target_pub:
                        return
                    chunks_out = []
                    max_len = target_pub.key_size // 8 - 66
                    for i in range(0, len(payload_bytes), max_len):
                        part = payload_bytes[i:i + max_len]
                        enc = target_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                    algorithm=hashes.SHA256(), label=None))
                        chunks_out.append(base64.b64encode(enc).decode())
                    direct_msg = {
                        "type": "handshake",
                        "id": handshake_id,
                        "initiator": initiator_id,
                        "target": target_id,
                        "stage": 12,
                        "chunks": chunks_out
                    }
                    # Отправляем напрямую (по существующему маршруту через сеть)
                    for neighbor in self.node.neighbors:
                        # передаём всем соседям, т.к. маршрут до B установился
                        self.node.send(neighbor, direct_msg)
                    log.info(f"Initiator {self.node.id}: sent direct DH params to target {target_id} (stage 12)")

            elif stage == 12.5:
                # Получен ответ B (Yb) на прямой DH-обмен (глава 12.9)
                chunks = msg.get("chunks", [])
                if not chunks or handshake_id not in self.ephemeral_states:
                    return
                # Расшифровать RSA-конверт приватным ключом A
                try:
                    full_bytes = b""
                    for ch in chunks:
                        enc = base64.b64decode(ch.encode())
                        part = self.node.rsa_priv.decrypt(enc, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                            algorithm=hashes.SHA256(), label=None))
                        full_bytes += part
                    resp = json.loads(full_bytes.decode())
                except Exception as e:
                    log.error(f"{self.node.id}: Failed to decrypt Yb from target: {e}")
                    return
                Yb = resp.get("Y")
                privA = self.ephemeral_states[handshake_id].get("final_priv")
                if Yb is None or privA is None:
                    return
                # Завершить вычисление общего секрета KD4
                shared_AB = privA.exchange(
                    dh.DHPublicNumbers(Yb, privA.public_key().public_numbers().parameter_numbers).public_key(
                        default_backend()))
                final_hash = hashes.Hash(hashes.SHA256())
                final_hash.update(shared_AB)
                key_bytes = final_hash.finalize()
                # Пометить handshake как завершённый
                self.completed_handshakes.add(handshake_id)
                # Очистить временное состояние
                self.ephemeral_states.pop(handshake_id, None)
                # Вызвать callback об успешном handshake
                if hasattr(self.node, "on_handshake_complete"):
                    self.node.on_handshake_complete(target_id, key_bytes)
                log.info(
                    f"Initiator {self.node.id}: handshake {handshake_id} complete. Tunnel to {target_id} established.")
            return

        # === Обработка на промежуточных узлах (X*) ===
        # Узел не является ни инициатором, ни финальным получателем handshake
        # Значит, этот узел находится на пути и должен пересылать/участвовать в промежуточных шагах.
        if initiator_id != self.node.id and target_id != self.node.id:
            # Защита от повторной обработки одного и того же handshake на этом узле
            if handshake_id in self.seen_handshakes and stage == 1:
                # Если уже видели начальный запрос, не будем пересылать повторно
                return

            # Помечаем handshake как виденный
            self.seen_handshakes.add(handshake_id)
            # Сохраняем маршрут обратно (откуда пришёл инициирующий запрос)
            if stage == 1:
                self.route_back[handshake_id] = from_id

            if stage == 1:
                # Глава 1 для промежуточного узла, который по отношению к A выступает X1 или далее.
                # Получен RSA-конверт от предыдущего узла (либо A, либо другой промежуточный) для установления DH.
                chunks = msg.get("chunks", [])
                if not chunks:
                    return
                # Расшифровать своим RSA-ключом
                try:
                    full = b""
                    for enc_chunk_b64 in chunks:
                        enc_chunk = base64.b64decode(enc_chunk_b64.encode())
                        part = self.node.rsa_priv.decrypt(enc_chunk, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                                  algorithm=hashes.SHA256(),
                                                                                  label=None))
                        full += part
                    payload = json.loads(full.decode())
                except Exception as e:
                    log.error(f"{self.node.id}: Failed to decrypt handshake stage1: {e}")
                    return
                # Извлечь DH параметры инициатора
                DH_p = payload["DH"]["p"]
                DH_g = payload["DH"]["g"]
                Ya = payload["DH"]["Y"]
                # Сгенерировать свои DH-числа
                params = dh.DHParameterNumbers(DH_p, DH_g).parameters(default_backend())
                priv = params.generate_private_key()
                Yx = priv.public_key().public_numbers().y
                # Вычислить общий секрет с отправителем (KD* для этого сегмента)
                shared = priv.exchange(
                    dh.DHPublicNumbers(Ya, dh.DHParameterNumbers(DH_p, DH_g)).public_key(default_backend()))
                kd_hash = hashes.Hash(hashes.SHA256());
                kd_hash.update(shared);
                kd_seg = kd_hash.finalize()
                # Сохраняем приватный ключ и KD для сегмента (self.node.id <-> from_id)
                self.ephemeral_states.setdefault(handshake_id, {})
                self.ephemeral_states[handshake_id]["priv"] = priv
                self.ephemeral_states[handshake_id]["kd_seg"] = kd_seg
                # Отправляем RSA-ответ (свой Yx) обратно отправителю
                resp_payload = {"SA": "sel", "nonce": secrets.token_hex(16), "DH": {"Y": Yx}}
                resp_bytes = json.dumps(resp_payload).encode()
                sender_pub = self.node.get_rsa_pub(from_id)
                if not sender_pub:
                    return
                try:
                    resp_enc = sender_pub.encrypt(resp_bytes, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                           algorithm=hashes.SHA256(), label=None))
                except Exception as e:
                    log.error(f"{self.node.id}: RSA encrypt error: {e}")
                    return
                resp_msg = {
                    "type": "handshake",
                    "id": handshake_id,
                    "initiator": initiator_id,
                    "target": target_id,
                    "stage": 1.5,
                    "blob": base64.b64encode(resp_enc).decode()
                }
                self.node.send(from_id, resp_msg)
                log.info(f"Node {self.node.id}: sent DH response to {from_id} (Y={Yx}) for handshake {handshake_id}")

            elif stage == 1.6:
                # Получен Auth Hash(A) от предыдущего узла по KD-сегменту
                kd_seg = self.ephemeral_states.get(handshake_id, {}).get("kd_seg")
                nonce_b64 = msg.get("nonce");
                cipher_b64 = msg.get("cipher")
                if not kd_seg or not nonce_b64 or not cipher_b64:
                    return
                try:
                    aead = ChaCha20Poly1305(kd_seg)
                    nonce = base64.b64decode(nonce_b64.encode())
                    cipher = base64.b64decode(cipher_b64.encode())
                    plain = aead.decrypt(nonce, cipher, None)
                    data = json.loads(plain.decode())
                    log.debug(f"{self.node.id}: received Auth Hash from {from_id}: {data}")
                except Exception as e:
                    log.error(f"{self.node.id}: Failed to decrypt auth from {from_id}: {e}")
                    return
                # Отправляем свой Auth-ответ (Hash(X)+II) обратно
                hash_val = hashes.Hash(hashes.SHA256());
                hash_val.update(self.node.id.encode());
                hashX = hash_val.finalize()
                resp_payload = {"Hash": hashX.hex(), "II": f"II({self.node.id}-{from_id})"}
                aead = ChaCha20Poly1305(kd_seg)
                nonce = secrets.token_bytes(12)
                cipher = aead.encrypt(nonce, json.dumps(resp_payload).encode(), None)
                resp_msg = {
                    "type": "handshake",
                    "id": handshake_id,
                    "initiator": initiator_id,
                    "target": target_id,
                    "stage": 1.6,
                    "nonce": base64.b64encode(nonce).decode(),
                    "cipher": base64.b64encode(cipher).decode()
                }
                self.node.send(from_id, resp_msg)
                log.info(f"{self.node.id}: sent Auth response to {from_id} over KD-seg for handshake {handshake_id}")
                # Теперь узел готов принять инструкцию I1 (MOVE) от инициатора

            elif stage == 2:
                # Получена инструкция I1="MOVE" от предыдущего узла – начатьHandshake со следующими соседями (глава 2.1–2.4)
                # Инициируем главу 3 с каждым соседом, кроме from_id
                for neighbor_id in self.node.neighbors:
                    if neighbor_id == from_id:
                        continue
                    # Генерируем новый DH для канала с neighbor_id
                    params = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
                    priv = params.generate_private_key()
                    Yx = priv.public_key().public_numbers().y
                    p = params.parameter_numbers().p
                    g = params.parameter_numbers().g
                    self.ephemeral_states.setdefault(handshake_id, {})
                    self.ephemeral_states[handshake_id].setdefault("dh_priv", {})[neighbor_id] = priv
                    self.ephemeral_states[handshake_id].setdefault("dh_params", {})[neighbor_id] = params
                    # Подготавливаем RSA-конверт для соседа
                    payload = {
                        "SA": f"SA({self.node.id}-{neighbor_id})",
                        "nonce": secrets.token_hex(16),
                        "DH": {"p": p, "g": g, "Y": Yx}
                    }
                    payload_bytes = json.dumps(payload).encode()
                    neighbor_pub = self.node.get_rsa_pub(neighbor_id)
                    if not neighbor_pub:
                        continue
                    # RSA-шифрование payload
                    rsa_chunks = []
                    max_len = neighbor_pub.key_size // 8 - 66
                    for i in range(0, len(payload_bytes), max_len):
                        part = payload_bytes[i:i + max_len]
                        enc = neighbor_pub.encrypt(part, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                      algorithm=hashes.SHA256(), label=None))
                        rsa_chunks.append(base64.b64encode(enc).decode())
                    msg_out = {
                        "type": "handshake",
                        "id": handshake_id,
                        "initiator": initiator_id,
                        "target": target_id,
                        "stage": 1,
                        "chunks": rsa_chunks
                    }
                    self.seen_handshakes.add(handshake_id)
                    self.route_back[handshake_id] = from_id  # маршрут назад к инициатору через from_id
                    self.node.send(neighbor_id, msg_out)
                    log.info(
                        f"{self.node.id}: forwarded handshake to neighbor {neighbor_id} for handshake {handshake_id}")

            elif stage == 1.5:
                # Промежуточный узел получает RSA-ответ (Y) от своего следующего соседа
                blob_b64 = msg.get("blob")
                if not blob_b64 or handshake_id not in self.ephemeral_states:
                    return
                try:
                    blob = base64.b64decode(blob_b64.encode())
                    resp = self.node.rsa_priv.decrypt(blob, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                                         algorithm=hashes.SHA256(), label=None))
                    data = json.loads(resp.decode())
                except Exception as e:
                    log.error(f"{self.node.id}: Failed to decrypt RSA response from neighbor: {e}")
                    return
                Y_next = data["DH"]["Y"]
                neighbor = from_id
                priv_key = self.ephemeral_states[handshake_id]["dh_priv"].get(neighbor)
                params = self.ephemeral_states[handshake_id]["dh_params"].get(neighbor)
                if not priv_key or not params:
                    return
                shared = priv_key.exchange(
                    dh.DHPublicNumbers(Y_next, params.parameter_numbers()).public_key(default_backend()))
                kd_hash = hashes.Hash(hashes.SHA256());
                kd_hash.update(shared);
                kd2 = kd_hash.finalize()
                self.ephemeral_states[handshake_id].setdefault("kd_keys", {})[neighbor] = kd2
                log.info(f"{self.node.id}: KD2 established with {neighbor} for handshake {handshake_id}")
                # Отправляем Auth Hash(X*) соседу
                hash_val = hashes.Hash(hashes.SHA256());
                hash_val.update(self.node.id.encode());
                hashX = hash_val.finalize()
                aead = ChaCha20Poly1305(kd2)
                nonce = secrets.token_bytes(12)
                cipher = aead.encrypt(nonce, json.dumps(
                    {"Hash": hashX.hex(), "II": f"II({self.node.id}-{neighbor})"}).encode(), None)
                auth_msg = {
                    "type": "handshake",
                    "id": handshake_id,
                    "initiator": initiator_id,
                    "target": target_id,
                    "stage": 1.6,
                    "nonce": base64.b64encode(nonce).decode(),
                    "cipher": base64.b64encode(cipher).decode()
                }
                self.node.send(neighbor, auth_msg)
                log.debug(f"{self.node.id}: sent Auth Hash to neighbor {neighbor}")

            elif stage == 1.6:
                # Промежуточный узел получает Auth-ответ от соседа
                nonce_b64 = msg.get("nonce");
                cipher_b64 = msg.get("cipher")
                kd2 = self.ephemeral_states.get(handshake_id, {}).get("kd_keys", {}).get(from_id)
                if not nonce_b64 or not cipher_b64 or not kd2:
                    return
                try:
                    aead = ChaCha20Poly1305(kd2)
                    nonce = base64.b64decode(nonce_b64.encode());
                    cipher = base64.b64decode(cipher_b64.encode())
                    plain = aead.decrypt(nonce, cipher, None)
                    data = json.loads(plain.decode())
                    log.debug(f"{self.node.id}: Auth response from {from_id} OK: {data}")
                except Exception as e:
                    log.error(f"{self.node.id}: Auth response decrypt failed: {e}")
                    return
                # Auth с соседом завершён, отправляем инициатору OK1 (если это X1 получает от X2)
                if "OK1" in self.ephemeral_states.get(handshake_id, {}):
                    # Если этот узел уже получил OK1 от своего соседа, пересылаем дальше
                    ok1_pem = self.ephemeral_states[handshake_id]["OK1"]
                    ok_msg = {
                        "type": "handshake",
                        "id": handshake_id,
                        "initiator": initiator_id,
                        "target": target_id,
                        "stage": 5.2,
                        "OK1": ok1_pem,
                        "I4": "OK_RECEIVED"
                    }
                    next_hop = self.route_back.get(handshake_id)
                    if next_hop:
                        self.node.send(next_hop, ok_msg)
                        log.info(f"{self.node.id}: forwarded OK1 to initiator via {next_hop}")
                else:
                    # Формируем собственный OK1 (открытый ключ) для передачи назад инициатору через цепочку
                    pem = self.node.get_rsa_pub_pem()
                    if pem:
                        self.ephemeral_states[handshake_id]["OK1"] = pem
                        ok_msg = {
                            "type": "handshake",
                            "id": handshake_id,
                            "initiator": initiator_id,
                            "target": target_id,
                            "stage": 5.2,
                            "OK1": pem,
                            "I4": "OK_RECEIVED"
                        }
                        next_hop = self.route_back.get(handshake_id)
                        if next_hop:
                            self.node.send(next_hop, ok_msg)
                            log.info(f"{self.node.id}: sent OK1({self.node.id}) back to initiator via {next_hop}")
            return
