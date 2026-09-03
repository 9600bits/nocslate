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


def migrate_legacy_key() -> bool:
    """Move a legacy plaintext API key into the DPAPI-backed provider vault."""
    path = config_path()
    try:
        with path.open("r", encoding="utf-8") as handle:
            stored = json.load(handle)
    except (OSError, ValueError, TypeError):
        return False
    legacy = str(stored.get("api_key") or "")
    if not legacy:
        return False
    temporary = path.with_suffix(path.suffix + ".migrating")
    try:
        from .ai_providers import save_provider
        from .infra_store import store
        credential = store.query_one("SELECT id FROM credential WHERE name=?", ("legacy-ai-key",))
        credential_id = credential["id"] if credential else store.create_credential(
            "legacy-ai-key", "api_key", legacy, {"migrated_from": str(path)}
        )["id"]
        existing = store.query_one("SELECT id FROM ai_provider WHERE name=?", ("Legacy AI provider",))
        save_provider({
            "name": "Legacy AI provider", "provider_type": "openai_compatible",
            "base_url": str(stored.get("base_url") or DEFAULTS["base_url"]),
            "chat_model": str(stored.get("model") or DEFAULTS["model"]),
            "embedding_model": "", "api_key_credential_id": credential_id, "active": True,
        }, existing["id"] if existing else None, store)
        replacement = dict(stored)
        replacement["api_key"] = ""
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(replacement, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        return True
    except Exception:
        temporary.unlink(missing_ok=True)
        return False
