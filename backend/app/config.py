from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

_lock = threading.Lock()

DEFAULTS = {
    "base_url": "https://api.deepseek.com/v1",
    "model": "deepseek-chat",
    "api_key": "",
}


def config_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "config.json"
    return Path(__file__).resolve().parent.parent / "config.json"


def load() -> dict:
    path = config_path()
    data = dict(DEFAULTS)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                stored = json.load(f)
            for key in DEFAULTS:
                if key in stored and stored[key] is not None:
                    data[key] = str(stored[key])
        except Exception:
            pass
    return data


def save(update: dict) -> dict:
    with _lock:
        data = load()
        for key in DEFAULTS:
            if key in update and update[key] is not None:
                data[key] = str(update[key])
        path = config_path()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError:
            raise RuntimeError(f"配置文件写入失败：{path}") from None
        return data


def mask_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return "***"
    return f"{key[:3]}{'*' * (len(key) - 6)}{key[-3:]}"
