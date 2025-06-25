from __future__ import annotations

import json, logging, secrets
from typing import Any, Dict, List, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh

from handshake.node  import Node, _dh_peer_pub
from handshake.utils import (
    rsa_encrypt, rsa_encrypt_long,
    rsa_decrypt, rsa_decrypt_long,
    sym_encrypt, sym_decrypt,
    sha256, trace,
)

log = logging.getLogger("crypto.handshake")


# ────────────────────────────────────────────────────────────
def run(
    X1: Node,
    X2: Node,
    *,
    chan_name: str = "X1-X2",
    sa_label: str  = "SA(X1-X2)",
) -> None:
    """Выполняет шаги 3.1 – 3.21 ТЗ и формирует KD2(chan_name)."""
    chan = chan_name
    log.info(
        "ГЛАВА 3. %s ↔ %s  IKEv2-фаза-1   [канал %s]",
        X1.name, X2.name, chan
    )

    # ─── 3.1  X1 генерирует DH-числа ────────────────────────────────
    p, g, Y1 = X1.dh_generate(chan)
    trace("3.1", X1.name, X1.name, "DH-gen", {"bits": p.bit_length()})

    # ─── 3.2  RSA-конверт для X2 (может быть длинным) ───────────────
    payload_32: Dict[str, Any] = {
        "SA": sa_label,
        "nonce": secrets.token_hex(16),
        "DH": {"p": p, "g": g, "Y": Y1},
    }
    blobs_32: List[bytes] = rsa_encrypt_long(
        X2.pub(), json.dumps(payload_32).encode()
    )
    trace("3.2", X1.name, X2.name, "RSA-long-enc", {"chunks": len(blobs_32)})

    # ─── 3.3  X1 «отправляет» X2 список чанков ----------------------
    X2.inbox.append(blobs_32)
    trace("3.3", X1.name, X2.name, "RSA-send", {"chunks": len(blobs_32)})

    # ─── 3.4 | 3.5  X2 принимает и расшифровывает -------------------
    recv_35: Union[bytes, List[bytes]] = X2.inbox.pop(0)
    trace("3.4", X2.name, X2.name, "RSA-recv",
          {"type": type(recv_35).__name__})

    plain_35 = (rsa_decrypt_long(X2.rsa_priv, recv_35)
                if isinstance(recv_35, list)
                else rsa_decrypt      (X2.rsa_priv, recv_35))
    msg_35 = json.loads(plain_35)
    trace("3.5", X2.name, X2.name, "RSA-dec", list(msg_35.keys()))

    # ─── 3.6  X2 формирует своё Y2 и KD2 ----------------------------
    DH_p, DH_g, Y1_recv = msg_35["DH"].values()
    prm2   = dh.DHParameterNumbers(DH_p, DH_g).parameters(default_backend())
    priv2  = prm2.generate_private_key()
    Y2     = priv2.public_key().public_numbers().y

    X2.dh_params[chan] = prm2
    X2.dh_privs [chan] = priv2
    X2.dh_peerY[chan]  = Y1_recv
    X2.dh_shared[chan] = priv2.exchange(_dh_peer_pub(DH_p, DH_g, Y1_recv))
    trace("3.6", X2.name, X2.name, f"DH({chan})", {"Y2": "…"})

    # ─── 3.7  X2 → X1  короткий RSA-ответ ---------------------------
    pkt_37  = {"SA": "sel", "nonce": secrets.token_hex(16), "DH": {"Y": Y2}}
    blob_37 = rsa_encrypt(X1.pub(), json.dumps(pkt_37).encode())
    X1.inbox.append(blob_37)
    trace("3.7", X2.name, X1.name, "RSA-send", {"bytes": len(blob_37)})

    # ─── 3.8  сеть (trace) -----------------------------------------
    trace("3.8", X2.name, X1.name, "network", {"bytes": len(blob_37)})

    # ─── 3.9 | 3.10  X1 принимает и расшифровывает ------------------
    blob_39 = X1.inbox.pop(0)
    trace("3.9", X1.name, X1.name, "RSA-recv", {"bytes": len(blob_39)})
    Y2_recv = json.loads(rsa_decrypt(X1.rsa_priv, blob_39))["DH"]["Y"]
    trace("3.10", X1.name, X1.name, "RSA-dec", ["Y"])

    # ─── 3.11  X1 завершает KD2 ------------------------------------
    X1.dh_set_peer(chan, Y2_recv)
    trace("3.11", X1.name, X1.name, f"KD2({chan})", {"status": "ready"})

    # ─── 3.12-3.16  X1 → X2  AUTH-хеш ------------------------------
    hash_X1 = sha256(b"X1")
    blob_313 = sym_encrypt(
        X1.dh_key(chan),
        json.dumps({"Hash": hash_X1, "II": f"II({X1.name}-{X2.name})"}).encode()
    )
    X2.inbox.append(blob_313)
    trace("3.13", X1.name, X2.name, f"DH({chan})-send", ["Hash", "II"])

    pkt_316 = json.loads(sym_decrypt(X2.dh_key(chan), X2.inbox.pop(0)))
    trace("3.16", X2.name, X2.name, f"DH({chan})-dec", list(pkt_316.keys()))

    # ─── 3.17-3.21  X2 → X1  AUTH-ответ -----------------------------
    hash_X2 = sha256(b"X2")
    blob_318 = sym_encrypt(
        X2.dh_key(chan),
        json.dumps({"Hash": hash_X2, "II": f"II({X2.name}-{X1.name})"}).encode()
    )
    X1.inbox.append(blob_318)
    trace("3.18", X2.name, X1.name, f"DH({chan})-send", ["Hash", "II"])

    pkt_321 = json.loads(sym_decrypt(X1.dh_key(chan), X1.inbox.pop(0)))
    trace("3.21", X1.name, X1.name, f"DH({chan})-dec", list(pkt_321.keys()))

    log.info("Глава 3 завершена  (канал %s)", chan)