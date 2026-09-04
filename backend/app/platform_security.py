"""Windows-local secret storage and defensive redaction helpers."""

from __future__ import annotations

import base64
import ctypes
import os
import re
import shutil
import sqlite3
import sys
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Any


SECRET_KEYS = {
    "api_key", "password", "passwd", "secret", "token", "private_key",
    "passphrase", "client_key", "client_certificate_data", "tokenfile",
}

_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)\b((?:api[_-]?key|password|passwd|secret|token|community|psk)\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S),
]

_PRIVATE_IP = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|127(?:\.\d{1,3}){3})\b"
)


def _migrate_legacy_data_dir(base: Path, target: Path) -> Path:
    legacy = base / "PacketLens"
    if target.exists() or not legacy.is_dir():
        return target

    staging = base / f".NOCSlate-migrating-{uuid.uuid4().hex}"
    try:
        staging.mkdir(parents=True)
        for source in legacy.iterdir():
            if source.name.endswith(("-wal", "-shm")):
                continue
            destination = staging / source.name
            if source.is_dir():
                shutil.copytree(source, destination)
            elif source.suffix.lower() == ".db":
                source_db = sqlite3.connect(str(source))
                target_db = sqlite3.connect(str(destination))
                try:
                    source_db.backup(target_db)
                finally:
                    target_db.close()
                    source_db.close()
                if source.name == "ops.db":
                    migrated_db = sqlite3.connect(str(destination))
                    try:
                        has_documents = migrated_db.execute(
                            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='knowledge_document'"
                        ).fetchone()
                        if has_documents:
                            rows = migrated_db.execute(
                                "SELECT id,file_path FROM knowledge_document WHERE file_path<>''"
                            ).fetchall()
                            for document_id, file_path in rows:
                                try:
                                    relative = Path(file_path).relative_to(legacy)
                                except ValueError:
                                    continue
                                migrated_db.execute(
                                    "UPDATE knowledge_document SET file_path=? WHERE id=?",
                                    (str(target / relative), document_id),
                                )
                        migrated_db.commit()
                    finally:
                        migrated_db.close()
            else:
                shutil.copy2(source, destination)
        # Rename within the same parent so the completed copy becomes visible
        # as one operation on Windows as well as POSIX.
        os.rename(staging, target)
        return target
    except (OSError, sqlite3.Error, shutil.Error):
        shutil.rmtree(staging, ignore_errors=True)
        return legacy


def app_data_dir() -> Path:
    override = os.environ.get("NOCSLATE_DATA_DIR") or os.environ.get("PACKET_LENS_DATA_DIR")
    if override:
        root = Path(override).expanduser().resolve()
    else:
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
        root = _migrate_legacy_data_dir(base, base / "NOCSlate")
    root.mkdir(parents=True, exist_ok=True)
    (root / "knowledge").mkdir(exist_ok=True)
    (root / "logs").mkdir(exist_ok=True)
    return root


def redact_text(value: str, mask_private_ips: bool = False) -> str:
    text = value or ""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda match: (match.group(1) if match.lastindex else "") + "[REDACTED]", text)
    if mask_private_ips:
        text = _PRIVATE_IP.sub("[PRIVATE-IP]", text)
    return text


def redact_data(value: Any, mask_private_ips: bool = False) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if str(key).lower() in SECRET_KEYS:
                result[key] = "[REDACTED]"
            else:
                result[key] = redact_data(item, mask_private_ips)
        return result
    if isinstance(value, list):
        return [redact_data(item, mask_private_ips) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_data(item, mask_private_ips) for item in value)
    if isinstance(value, str):
        return redact_text(value, mask_private_ips)
    return value


def mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 6:
        return "••••••"
    return f"{value[:2]}{'•' * min(12, len(value) - 4)}{value[-2:]}"


class SecretProtectionError(RuntimeError):
    pass


if sys.platform == "win32":
    class _DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _make_blob(data: bytes):
    buffer = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    return blob, buffer


def _dpapi(value: bytes, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise SecretProtectionError("DPAPI 仅在 Windows 上可用")
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    in_blob, in_buffer = _make_blob(value)
    out_blob = _DataBlob()
    flags = 0x01  # CRYPTPROTECT_UI_FORBIDDEN
    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(in_blob), "NOCSlate", None, None, None, flags, ctypes.byref(out_blob)
        )
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(in_blob), None, None, None, None, flags, ctypes.byref(out_blob)
        )
    # Keep the backing buffer alive until CryptProtectData/CryptUnprotectData returns.
    _ = in_buffer
    if not ok:
        raise SecretProtectionError(f"Windows DPAPI 操作失败: {ctypes.get_last_error()}")
    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def protect_secret(value: str) -> str:
    if not value:
        return ""
    return base64.b64encode(_dpapi(value.encode("utf-8"), True)).decode("ascii")


def unprotect_secret(value: str) -> str:
    if not value:
        return ""
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
        return _dpapi(raw, False).decode("utf-8")
    except (ValueError, UnicodeError) as exc:
        raise SecretProtectionError("凭据数据损坏或不属于当前 Windows 用户") from exc


def write_windows_credential(target: str, username: str, password: str) -> None:
    """Store an opt-in RDP credential using Windows Credential Manager."""
    if sys.platform != "win32":
        raise SecretProtectionError("Windows 凭据管理器仅在 Windows 上可用")

    class _Credential(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)), ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR),
        ]

    blob = password.encode("utf-16-le")
    buffer = ctypes.create_string_buffer(blob, len(blob))
    credential = _Credential()
    credential.Type = 1  # CRED_TYPE_GENERIC; matches cmdkey /generic:TERMSRV/host
    credential.TargetName = target
    credential.UserName = username
    credential.CredentialBlobSize = len(blob)
    credential.CredentialBlob = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
    credential.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE
    credential.Comment = "NOCSlate RDP"
    if not ctypes.windll.advapi32.CredWriteW(ctypes.byref(credential), 0):
        raise SecretProtectionError(f"写入 Windows 凭据失败: {ctypes.get_last_error()}")


def delete_windows_credential(target: str) -> None:
    if sys.platform != "win32":
        return
    if not ctypes.windll.advapi32.CredDeleteW(target, 1, 0):
        error = ctypes.get_last_error()
        if error != 1168:  # ERROR_NOT_FOUND
            raise SecretProtectionError(f"删除 Windows 凭据失败: {error}")
