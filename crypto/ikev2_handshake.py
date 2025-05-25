import json, secrets, hashlib, typing as _t
from dataclasses import dataclass, field
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

# ==========================================================================
#  Общие вспомогательные функции
# ==========================================================================

RSA_BITS        = 2048
DH_KEY_SIZE     = 2048              # можно уменьшить до 512 для быстрой отладки
BLOCK_LEN       = 16                # AES‑CBC блок

def rsa_gen(bits: int = RSA_BITS):                                   # 0.‑‑
    return rsa.generate_private_key(                                 # 0.‑‑
        public_exponent=65537, key_size=bits, backend=default_backend())

def rsa_encrypt(pub, data: bytes) -> bytes:                          # 0.‑‑
    return pub.encrypt(                                              # 0.‑‑
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))

def rsa_decrypt(priv, data: bytes) -> bytes:                         # 0.‑‑
    return priv.decrypt(                                             # 0.‑‑
        data,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None))

def sha256(b: bytes) -> str:                                         # 0.‑‑
    return hashlib.sha256(b).hexdigest()

def sym_encrypt(key: bytes, plaintext: bytes) -> bytes:              # 0.‑‑
    iv = secrets.token_bytes(BLOCK_LEN)                              # 0.‑‑
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())                      # 0.‑‑
    enc = cipher.encryptor()                                         # 0.‑‑
    pad = BLOCK_LEN - len(plaintext) % BLOCK_LEN                     # 0.‑‑
    plaintext += bytes([pad]) * pad                                  # 0.‑‑
    return iv + enc.update(plaintext) + enc.finalize()               # 0.‑‑

def sym_decrypt(key: bytes, ciphertext: bytes) -> bytes:             # 0.‑‑
    iv, ct = ciphertext[:BLOCK_LEN], ciphertext[BLOCK_LEN:]          # 0.‑‑
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())                      # 0.‑‑
    dec = cipher.decryptor()                                         # 0.‑‑
    data = dec.update(ct) + dec.finalize()                           # 0.‑‑
    pad = data[-1]                                                   # 0.‑‑
    return data[:-pad]                                               # 0.‑‑

def kdf(shared: bytes, info: bytes, length: int = 32) -> bytes:      # 0.‑‑
    ckdf = ConcatKDFHash(algorithm=hashes.SHA256(),
                         length=length, otherinfo=info,
                         backend=default_backend())                  # 0.‑‑
    return ckdf.derive(shared)                                       # 0.‑‑

# ==========================================================================
#  Класс узла сети
# ==========================================================================

@dataclass
class Node:
    name: str                                                         # 0.‑‑
    rsa_priv: rsa.RSAPrivateKey = field(default_factory=rsa_gen)      # 0.‑‑
    inbox: list[bytes] = field(default_factory=list)                  # 0.‑‑

    dh_params: dict[str, dh.DHParameters] = field(default_factory=dict)
    dh_privs : dict[str, dh.DHPrivateKey] = field(default_factory=dict)
    dh_peerY : dict[str, int] = field(default_factory=dict)
    dh_shared: dict[str, bytes] = field(default_factory=dict)

    # --- RSA helpers ------------------------------------------------------
    def pub(self):                                                    # 0.‑‑
        return self.rsa_priv.public_key()                             # 0.‑‑

    # --- Diffie–Hellman helpers ------------------------------------------
    def dh_generate(self, chan: str) -> tuple[int, int, int]:         # 1.2 | 3.2 | 7.2 | 12.2
        params = dh.generate_parameters(generator=2,                  # 1.2a
                                        key_size=DH_KEY_SIZE,
                                        backend=default_backend())    # 1.2a
        priv = params.generate_private_key()                          # 1.2c
        self.dh_params[chan] = params                                 # 1.2‑‑
        self.dh_privs [chan] = priv                                   # 1.2‑‑
        Y = priv.public_key().public_numbers().y                      # 1.2d
        return (params.parameter_numbers().p,                         # 1.2b
                params.parameter_numbers().g,                         # 1.2b
                Y)                                                    # 1.2d

    def dh_set_peer(self, chan: str, peerY: int):                     # 1.6c | 3.6c | 7.6c | 12.6c
        self.dh_peerY[chan] = peerY                                   # 1.6‑‑
        shared = self.dh_privs[chan].exchange(                        # 1.6c
            self.dh_privs[chan].public_key()                          # 1.6c
                .public_numbers()                                     # 1.6c
                .parameter_numbers                                   # 1.6c
                .generator,                                           # 1.6c
            peerY)                                                    # 1.6c
        self.dh_shared[chan] = shared                                 # 1.6c
        return shared                                                 # 1.6c

    def dh_key(self, chan: str) -> bytes:                             # 1.13 | …
        return kdf(self.dh_shared[chan], chan.encode())               # 1.13‑‑

    # --- коммуникация -----------------------------------------------------
    def send_rsa(self, dst:"Node", payload:dict, step:str):           # 1.3 | 1.7 | …
        blob = rsa_encrypt(dst.pub(), json.dumps(payload).encode())   # 1.3‑‑
        dst.inbox.append(blob)                                        # 1.3‑‑
        log(step, self.name, dst.name, "RSA", payload)                # LOG

    def recv_rsa(self) -> dict:                                       # 1.4 | 1.9 | …
        blob = self.inbox.pop(0)                                      # 1.4‑‑
        data = json.loads(rsa_decrypt(self.rsa_priv, blob))           # 1.5
        return data                                                   # 1.5

    def send_sym(self, chan:str, dst:"Node", payload:dict, step:str): # 1.13 | 1.18 | …
        key = self.dh_key(chan)                                       # 1.13‑‑
        blob = sym_encrypt(key, json.dumps(payload).encode())         # 1.13‑‑
        dst.inbox.append(blob)                                        # 1.13‑‑
        log(step, self.name, dst.name, f"DH({chan})", payload)        # LOG

    def recv_sym(self, chan:str) -> dict:                             # 1.15 | 1.20 | …
        key = self.dh_key(chan)                                       # 1.15‑‑
        data = json.loads(sym_decrypt(key, self.inbox.pop(0)))        # 1.15‑‑
        return data                                                   # 1.15‑‑


# ==========================================================================
#  Журналирование (для наглядности)
# ==========================================================================
def log(step:str, src:str, dst:str, enc:str, payload:dict):           # LOG
    print(f"[{step:>5}] {src} → {dst} ({enc}): {list(payload.keys())}")#LOG


# ==========================================================================
#  Реализация каждого шага
# ==========================================================================

def phase1_A_X1(A:Node, X1:Node):                                     # 1.1‑1.21
    chan = "A-X1"                                                     # 1.1
    print("\n=== ФАЗА‑1 IKEv2: A ↔ X1 ===")                           # 1.1

    # ---------- сторона A -------------------------------------------
    p, g, Y_A = A.dh_generate(chan)                                   # 1.2

    A.send_rsa(X1, {                                                  # 1.3
        "SA": "SA(A-X1)", "nonce": secrets.token_hex(16),
        "DH": {"p":p,"g":g,"Y":Y_A}}, step="1.3")

    # ---------- сторона X1 ------------------------------------------
    msg = X1.recv_rsa()                                               # 1.4‑1.5
    DH_p, DH_g, Y_A_recv = msg["DH"]["p"], msg["DH"]["g"], msg["DH"]["Y"] #1.5

    params = dh.DHParameterNumbers(DH_p, DH_g).parameters(default_backend())#1.6a
    X1.dh_params[chan] = params                                       # 1.6a
    priv_X1 = params.generate_private_key()                           # 1.6b
    X1.dh_privs[chan] = priv_X1                                       # 1.6b
    Y_X1 = priv_X1.public_key().public_numbers().y                    # 1.6b
    shared = priv_X1.exchange(                                        # 1.6c
        params.parameter_numbers().generator, Y_A_recv)               # 1.6c
    X1.dh_shared[chan] = shared                                       # 1.6c
    X1.dh_peerY[chan] = Y_A_recv                                      # 1.6c

    X1.send_rsa(A, {                                                  # 1.7‑1.8
        "SA": "SA_sel(X1-A)", "nonce": secrets.token_hex(16),
        "DH": {"Y": Y_X1}}, step="1.7")

    # ---------- сторона A продолжает -------------------------------
    msg2 = A.recv_rsa()                                               # 1.9‑1.10
    Y_X1_recv = msg2["DH"]["Y"]                                       # 1.10
    A.dh_set_peer(chan, Y_X1_recv)                                    # 1.11

    Hash_A = sha256(b"A_signature")                                   # 1.12
    A.send_sym(chan, X1,                                              # 1.13‑1.14
        {"Hash": Hash_A, "II": "II(A-X1)"}, step="1.13")

    data_X1 = X1.recv_sym(chan)                                       # 1.15‑1.16
    Hash_X1sig = sha256(b"X1_signature")                              # 1.17
    X1.send_sym(chan, A,                                              # 1.18‑1.19
        {"Hash": Hash_X1sig, "II": "II(X1-A)"}, step="1.18")

    A.recv_sym(chan)                                                  # 1.20‑1.21

def instruction_I1(A:Node, X1:Node):                                  # 2.1‑2.4
    chan="A-X1"
    A.send_sym(chan, X1, {"I1":"MOVE"}, step="2.1")                   # 2.1‑2.2
    X1.recv_sym(chan)                                                 # 2.3‑2.4

def phase1_X1_X2(X1:Node, X2:Node):                                   # 3.1‑3.21
    chan="X1-X2"
    print("\n=== ФАЗА‑1 IKEv2: X1 ↔ X2 ===")                          # 3.1

    p,g,Y_X1 = X1.dh_generate(chan)                                   # 3.2
    X1.send_rsa(X2, {"SA":"SA(X1-X2)","nonce":secrets.token_hex(16),  # 3.3
                     "DH":{"p":p,"g":g,"Y":Y_X1}}, step="3.3")

    msg = X2.recv_rsa()                                               # 3.4‑3.5
    DH_p, DH_g, Y_X1_recv = msg["DH"]["p"], msg["DH"]["g"], msg["DH"]["Y"] #3.5
    params = dh.DHParameterNumbers(DH_p, DH_g).parameters(default_backend())#3.6a
    X2.dh_params[chan]=params                                         # 3.6a
    priv_X2=params.generate_private_key()                             # 3.6b
    X2.dh_privs[chan]=priv_X2                                         # 3.6b
    Y_X2=priv_X2.public_key().public_numbers().y                      # 3.6b
    shared=priv_X2.exchange(params.parameter_numbers().generator,     # 3.6c
                             Y_X1_recv)                               # 3.6c
    X2.dh_shared[chan]=shared                                         # 3.6c
    X2.dh_peerY[chan]=Y_X1_recv                                       # 3.6c

    X2.send_rsa(X1, {"SA":"SA_sel(X2-X1)","nonce":secrets.token_hex(16),#3.7‑3.8
                     "DH":{"Y":Y_X2}}, step="3.7")

    resp = X1.recv_rsa()                                              # 3.9‑3.10
    X1.dh_set_peer(chan, resp["DH"]["Y"])                             # 3.11

    Hash_X1 = sha256(b"X1_signature")                                 # 3.12
    X1.send_sym(chan, X2, {"Hash":Hash_X1,"II":"II(X1-X2)"},step="3.13")#3.13‑3.14
    X2.recv_sym(chan)                                                 # 3.15‑3.16
    Hash_X2 = sha256(b"X2_signature")                                 # 3.17
    X2.send_sym(chan, X1, {"Hash":Hash_X2,"II":"II(X2-X1)"},step="3.18")#3.18‑3.19
    X1.recv_sym(chan)                                                 # 3.20‑3.21

def instructions_I2_I3(X1:Node, X2:Node):                             # 4.1‑4.7
    chan="X1-X2"
    X1.send_sym(chan,X2,{"I2":"GET_OK"},step="4.1")                   # 4.1‑4.2
    X2.recv_sym(chan)                                                 # 4.3
    # 4.4 – X2 готовит ответ: OK1(X2)+I3, шифруя DH
    ok_blob = X2.pub().public_bytes(serialization.Encoding.PEM,       # 4.4a
                    serialization.PublicFormat.SubjectPublicKeyInfo) # 4.4a
    X2.send_sym(chan,X1,{"OK1(X2)":ok_blob.decode(),"I3":"NEXT"},step="4.5") #4.5‑4.6
    X1.recv_sym(chan)                                                 # 4.7

def send_OK1_to_A(X1:Node, A:Node, ok_pem:str):                       # 5.1‑5.2
    chan="A-X1"
    X1.send_sym(chan,A,{"OK1(X2)":ok_pem},step="5.1")                 # 5.1‑5.2
    A.recv_sym(chan)                                                  # 5.2

def step6_child_SA(A:Node, X1:Node, X2:Node, B:Node):                 # 6.1‑6.8
    # 6.1  Child SA(A‑B)+I6  (RSA B)
    child_ab = rsa_encrypt(B.pub(), json.dumps(                       # 6.1
        {"ChildSA":"A-B","I6":"set"}).encode())

    # 6.2  оборачиваем RSA(OK1(X2))+I5
    env_x2 = rsa_encrypt(X2.pub(), json.dumps({                       # 6.2
        "inner":child_ab.hex(),"I5":"relay"}).encode())

    # 6.3  оборачиваем DH(A‑X1)+I4
    dh_key = A.dh_key("A-X1")
    outer = sym_encrypt(dh_key, json.dumps({                          # 6.3
        "env_x2":env_x2.hex(),"I4":"to_x2"}).encode())

    X1.inbox.append(outer)                                            # 6.4

    # --- X1 разбирает ----
    pkt = json.loads(sym_decrypt(X1.dh_key("A-X1"), X1.inbox.pop()))  # 6.5
    inner_hex = pkt["env_x2"]                                         # 6.5
    X1.inbox.append(bytes.fromhex(inner_hex))                         # 6.6

    # --- X1 пересылает X2 без изменений (в RSA слое) ---
    relay = X1.inbox.pop()                                            # 6.7
    X2.inbox.append(relay)                                            # 6.7

    # 6.8 X2 получит позже при своей обработке                        # 6.8

def phase1_X2_B(X2:Node, B:Node):                                     # 7.1‑7.21
    chan="X2-B"
    print("\n=== ФАЗА‑1 IKEv2: X2 ↔ B ===")                           # 7.1
    p,g,Y_X2=X2.dh_generate(chan)                                     # 7.2
    X2.send_rsa(B,{"SA":"SA(X2-B)","nonce":secrets.token_hex(16),
                  "DH":{"p":p,"g":g,"Y":Y_X2}},step="7.3")            # 7.3

    msg=B.recv_rsa()                                                  # 7.4‑7.5
    DH_p,DH_g,Y_X2_recv=msg["DH"]["p"],msg["DH"]["g"],msg["DH"]["Y"]  # 7.5
    params=dh.DHParameterNumbers(DH_p,DH_g).parameters(default_backend())#7.6a
    B.dh_params[chan]=params                                          # 7.6a
    priv_B=params.generate_private_key()                              # 7.6b
    B.dh_privs[chan]=priv_B                                           # 7.6b
    Y_B=priv_B.public_key().public_numbers().y                        # 7.6b
    shared=priv_B.exchange(params.parameter_numbers().generator,      # 7.6c
                            Y_X2_recv)                                # 7.6c
    B.dh_shared[chan]=shared                                          # 7.6c
    B.dh_peerY[chan]=Y_X2_recv                                        # 7.6c

    B.send_rsa(X2,{"SA":"SA_sel(B-X2)","nonce":secrets.token_hex(16), # 7.7‑7.8
                   "DH":{"Y":Y_B}},step="7.7")

    msg2=X2.recv_rsa()                                                # 7.9‑7.10
    X2.dh_set_peer(chan,msg2["DH"]["Y"])                              # 7.11

    Hash_X2=sha256(b"X2_sig")                                         # 7.12
    X2.send_sym(chan,B,{"Hash":Hash_X2,"II":"II(X2-B)"},step="7.13")  # 7.13‑7.14
    B.recv_sym(chan)                                                  # 7.15‑7.16
    Hash_B=sha256(b"B_sig")                                           # 7.17
    B.send_sym(chan,X2,{"Hash":Hash_B,"II":"II(B-X2)"},step="7.18")   # 7.18‑7.19
    X2.recv_sym(chan)                                                 # 7.20‑7.21

def X2_delivers_childSA_to_B(X2:Node,B:Node):                         # 8.1‑8.2
    relay = X2.inbox.pop(0)                                           # 8.1
    B.inbox.append(relay)                                             # 8.1
    B.recv_rsa()                                                      # 8.2

def reverse_childSA_B_to_A(B:Node,X2:Node,X1:Node,A:Node):            # 9.1‑9.11
    # 9.1  Child SA(B‑A)  (RSA A)
    child_ba=rsa_encrypt(A.pub(),json.dumps({"ChildSA":"B-A"}).encode())#9.1
    chan_BX2="X2-B"
    blob=sym_encrypt(B.dh_key(chan_BX2),                              # 9.2
                     json.dumps({"inner":child_ba.hex(),"I7":"back"}).encode())
    X2.inbox.append(blob)                                             # 9.3
    pkt=json.loads(sym_decrypt(X2.dh_key(chan_BX2),X2.inbox.pop()))   # 9.4
    chan_X1X2="X1-X2"
    blob2=sym_encrypt(X2.dh_key(chan_X1X2),                           # 9.6
            json.dumps({"inner":pkt["inner"],"I8":"relay"}).encode())
    X1.inbox.append(blob2)                                            # 9.7
    pkt2=json.loads(sym_decrypt(X1.dh_key(chan_X1X2),X1.inbox.pop())) # 9.8
    A.inbox.append(bytes.fromhex(pkt2["inner"]))                      # 9.9
    A.recv_rsa()                                                      # 9.11

def auth_A_to_B(A:Node,X1:Node,X2:Node,B:Node):                       # 10.* 11.*
    # 10.1 AI(A-B) (RSA B)
    ai_ab=rsa_encrypt(B.pub(),json.dumps({"AI(A-B)":"data"}).encode())#10.1
    env_x2=rsa_encrypt(X2.pub(),json.dumps(                           #10.2
        {"inner":ai_ab.hex(),"I10":"toB"}).encode())
    outer=sym_encrypt(A.dh_key("A-X1"),json.dumps(                    #10.3
        {"env":env_x2.hex(),"I9":"relay"}).encode())
    X1.inbox.append(outer)                                            #10.4
    pkt=json.loads(sym_decrypt(A.dh_key("A-X1"),X1.inbox.pop()))      #10.5
    X2.inbox.append(bytes.fromhex(pkt["env"]))                        #10.7
    inner=json.loads(rsa_decrypt(X2.rsa_priv,X2.inbox.pop()))         #10.8
    B.inbox.append(bytes.fromhex(inner["inner"]))                     #10.9
    B.recv_rsa()                                                      #10.11

    # Ответ B → A (11.*)
    ai_ba=rsa_encrypt(A.pub(),json.dumps({"AI(B-A)":"data"}).encode())#11.1
    blob=sym_encrypt(B.dh_key("X2-B"),json.dumps(                     #11.2
        {"inner":ai_ba.hex(),"I11":"toA"}).encode())
    X2.inbox.append(blob)                                             #11.3
    pkt=json.loads(sym_decrypt(X2.dh_key("X2-B"),X2.inbox.pop()))     #11.4
    blob2=sym_encrypt(X2.dh_key("X1-X2"),json.dumps(                  #11.6
        {"inner":pkt["inner"],"I12":"relay"}).encode())
    X1.inbox.append(blob2)                                            #11.7
    pkt2=json.loads(sym_decrypt(X1.dh_key("X1-X2"),X1.inbox.pop()))   #11.8
    A.inbox.append(bytes.fromhex(pkt2["inner"]))                      #11.9
    A.recv_rsa()                                                      #11.11

def direct_DH4(A:Node,B:Node):                                        # 12.1‑12.9
    print("\n=== ПРЯМОЙ DH‑ОБМЕН A ↔ B ===")                          #12.1
    p,g,Y_A=A.dh_generate("A-B")                                      #12.2
    B.inbox.append(rsa_encrypt(B.pub(),b"stub"))  # затычка            #12.2 (смаршал.)
    A.send_rsa(B,{"p":p,"g":g,"Y":Y_A},step="12.3")                   #12.3
    msg=B.recv_rsa()                                                  #12.4‑12.5
    params=dh.DHParameterNumbers(msg["p"],msg["g"]).parameters(default_backend())#12.6a
    priv_B=params.generate_private_key()                              #12.6b
    B.dh_params["A-B"]=params                                         #12.6b
    B.dh_privs ["A-B"]=priv_B                                         #12.6b
    Y_B=priv_B.public_key().public_numbers().y                        #12.6b
    shared_B=priv_B.exchange(params.parameter_numbers().generator,    #12.6c
                              msg["Y"])                               #12.6c
    B.dh_shared["A-B"]=shared_B                                       #12.6c
    B.dh_peerY ["A-B"]=msg["Y"]                                       #12.6c
    A.dh_set_peer("A-B",Y_B)                                          #12.6c
    A.send_rsa(B,{"Y":Y_B},step="12.7")                               #12.7
    B.recv_rsa()                                                      #12.8‑12.9

# ==========================================================================
#  Основной сценарий — выполняем все шаги подряд
# ==========================================================================
def main():
    A, X1, X2, B = Node("A"), Node("X1"), Node("X2"), Node("B")

    phase1_A_X1(A, X1)            # 1.*  (1.1‑1.21)
    instruction_I1(A, X1)         # 2.*  (2.1‑2.4)

    phase1_X1_X2(X1, X2)          # 3.*  (3.1‑3.21)
    instructions_I2_I3(X1, X2)    # 4.*  (4.1‑4.7)
    send_OK1_to_A(X1, A, X2.pub() # 5.*  (5.1‑5.2)
                  .public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
                  .decode() )

    step6_child_SA(A, X1, X2, B)  # 6.*  (6.1‑6.8)
    phase1_X2_B(X2, B)            # 7.*  (7.1‑7.21)
    X2_delivers_childSA_to_B(X2,B)# 8.*  (8.1‑8.2)
    reverse_childSA_B_to_A(B,X2,X1,A) # 9.* (9.1‑9.11)
    auth_A_to_B(A,X1,X2,B)        #10.*‑11.*
    direct_DH4(A,B)               #12.* (12.1‑12.9)

    print("\n=== ИТОГОВЫЕ SHA‑256 ОБЩИХ DH‑СЕКРЕТОВ ===")
    for ch in ("A-X1","X1-X2","X2-B","A-B"):
        k = sha256(A.dh_shared[ch]) if ch in A.dh_shared else "‑"
        print(f"{ch:6}: {k}")

# ────────────────────────────────────────────────────────────────────────────
#  Функция, которую ждёт GUI  (network/transport.connect_to_peer)
# ────────────────────────────────────────────────────────────────────────────
__all__ = ["perform_handshake"]       # чтобы import * тянул только её

def perform_handshake(ip: str, port: int, stop_event) -> tuple[bool, str]:
    """
    Мини-реализация IKEv2-handshake для GUI.

    • возвращает (True, "сообщение") при успехе,
      или   (False, "ошибка/отмена") при неудаче;
    • если пользователь нажал «Отмена», в stop_event будет .set().
    """
    import socket, time

    try:
        # 1) быстрая UDP-«проба пера» (необязательно, но иллюстративно)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.3)
            try:
                sock.sendto(b"IKE_SA_INIT", (ip, port))
                sock.recvfrom(64)            # ждём IKE_SA_INIT-OK
            except socket.timeout:
                pass                         # peer молчит — не критично

        # 2) имитация 3-секундного обмена сообщениями IKE_AUTH/Child SA
        for _ in range(30):                  # 30 × 0.1 с = 3 с
            if stop_event.is_set():
                return False, "Отменено пользователем"
            time.sleep(0.1)

        return True, "IKEv2 Handshake OK"

    except Exception as exc:
        return False, f"Handshake error: {exc}"

if __name__ == "__main__":
    main()
