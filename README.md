# P2P VPN Demo

This repository contains a small proof‑of‑concept of a peer‑to‑peer VPN written in Python. The application provides a PyQt5 based GUI and a set of helpers for discovery, key management and a simple encrypted handshake.

## Modules Overview

- **`auth.py` / `config.py`** – user login routine, static user list and default ports.
- **`crypto/`** – RSA and Diffie–Hellman helpers with a sample IKEv2‑like handshake.
- **`network/`** – UDP transport, peer discovery and packet helpers (both sync and async variants).
- **`ui/`** – PyQt5 windows: login dialog, network view and chat example.
- **`key_manager.py`** – in‑memory storage of temporary RSA keys.
- **`utils.py`** – logging and helper utilities.

Sample RSA keys (`rsa_key*_public.pem` / `rsa_key*_private.pem`) are included for demonstration purposes only and should not be used in production.

## Running

Install the dependencies listed in `requirements.txt` and start the GUI with:

```bash
python main.py
```

After login you can discover peers on the local network and initiate a connection.
