# utils.py
# -*- coding: utf-8 -*-
"""
Общие утилиты: логирование, сериализация/десериализация, тайминги.
"""

import json
import logging
import pathlib
from datetime import datetime
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# Логирование
# ---------------------------------------------------------------------------
_LOG_FORMAT = (
    "%(asctime)s [%(levelname).1s] %(name)s │ "
    "%(message)s (%(filename)s:%(lineno)d)"
)


def setup_logging(level: int = logging.DEBUG,
                  log_file: str | None = None) -> None:
    """Конфигурирует logging один раз в начале программы."""
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format=_LOG_FORMAT,
        handlers=handlers,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Сериализация
# ---------------------------------------------------------------------------

def to_json(data: Any, *, pretty: bool = False) -> str:
    return json.dumps(
        data,
        ensure_ascii=False,
        indent=4 if pretty else None,
        separators=(", ", ": ") if pretty else (",", ":"),
    )


def from_json(raw: str | bytes) -> Any:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    return json.loads(raw)


# ─────────────────────────────────────────────────────────────────────────────
# Разное
# ---------------------------------------------------------------------------

def timestamp() -> str:
    """ISO‑8601 метка времени в локальном часовом поясе."""
    return datetime.now().isoformat(timespec="seconds")


def ensure_dir(path: str | pathlib.Path) -> pathlib.Path:
    """Создать каталог, если его ещё нет. Вернуть pathlib.Path."""
    p = pathlib.Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p
