"""Persistent storage for the local infrastructure workspace."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .platform_security import app_data_dir, mask_secret, protect_secret, unprotect_secret


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_path() -> Path:
    return app_data_dir() / "ops.db"


def _loads(value: str | None, default: Any) -> Any:
    try:
        return json.loads(value or "")
    except (TypeError, ValueError):
        return default


class OpsStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS credential (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL,
                    secret_blob TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_used_at TEXT
                );
                CREATE TABLE IF NOT EXISTS server_profile (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    host TEXT NOT NULL,
                    os_hint TEXT NOT NULL DEFAULT 'linux',
                    environment TEXT NOT NULL DEFAULT '',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    remark TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS connection_profile (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL REFERENCES server_profile(id) ON DELETE CASCADE,
                    protocol TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    username TEXT NOT NULL DEFAULT '',
                    domain TEXT NOT NULL DEFAULT '',
                    auth_method TEXT NOT NULL DEFAULT 'password',
                    credential_id INTEGER REFERENCES credential(id) ON DELETE SET NULL,
                    private_key_id INTEGER REFERENCES credential(id) ON DELETE SET NULL,
                    passphrase_id INTEGER REFERENCES credential(id) ON DELETE SET NULL,
                    jump_connection_id INTEGER REFERENCES connection_profile(id) ON DELETE SET NULL,
                    allow_sudo INTEGER NOT NULL DEFAULT 0,
                    settings_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(server_id, protocol)
                );
                CREATE TABLE IF NOT EXISTS inspection_task (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL REFERENCES server_profile(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    profiles_json TEXT NOT NULL DEFAULT '[]',
                    interval_seconds INTEGER NOT NULL DEFAULT 1800,
                    enabled INTEGER NOT NULL DEFAULT 0,
                    last_run_at TEXT,
                    next_run_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS inspection_run (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    server_id INTEGER NOT NULL REFERENCES server_profile(id) ON DELETE CASCADE,
                    task_id INTEGER REFERENCES inspection_task(id) ON DELETE SET NULL,
                    trigger TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    snapshot_json TEXT NOT NULL DEFAULT '{}',
                    diff_json TEXT NOT NULL DEFAULT '[]',
                    summary TEXT NOT NULL DEFAULT '',
                    error TEXT NOT NULL DEFAULT '',
                    favorite INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS diagnostic_plan (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    options_json TEXT NOT NULL DEFAULT '{}',
                    steps_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    approved_at TEXT
                );
                CREATE TABLE IF NOT EXISTS diagnostic_run (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plan_id INTEGER REFERENCES diagnostic_plan(id) ON DELETE SET NULL,
                    status TEXT NOT NULL,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    timeline_json TEXT NOT NULL DEFAULT '[]',
                    summary TEXT NOT NULL DEFAULT '',
                    favorite INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS event (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_type TEXT NOT NULL,
                    source_id TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    acknowledged_at TEXT
                );
                CREATE TABLE IF NOT EXISTS knowledge_document (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_ref TEXT NOT NULL DEFAULT '',
                    sha256 TEXT NOT NULL UNIQUE,
                    file_path TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    favorite INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS knowledge_chunk (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    document_id INTEGER NOT NULL REFERENCES knowledge_document(id) ON DELETE CASCADE,
                    chunk_index INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    search_text TEXT NOT NULL,
                    embedding_json TEXT,
                    embedding_model TEXT NOT NULL DEFAULT '',
                    UNIQUE(document_id, chunk_index)
                );
                CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
                    chunk_id UNINDEXED, title, search_text, tokenize='unicode61'
                );
                CREATE TABLE IF NOT EXISTS ai_provider (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    provider_type TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    chat_model TEXT NOT NULL DEFAULT '',
                    embedding_model TEXT NOT NULL DEFAULT '',
                    api_key_credential_id INTEGER REFERENCES credential(id) ON DELETE SET NULL,
                    active INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS assistant_conversation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    provider_id INTEGER REFERENCES ai_provider(id) ON DELETE SET NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    favorite INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS assistant_message (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id INTEGER NOT NULL REFERENCES assistant_conversation(id) ON DELETE CASCADE,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    sources_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS network_plan (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    base_cidr TEXT NOT NULL,
                    requirements_json TEXT NOT NULL DEFAULT '[]',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    notes TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_connection_server ON connection_profile(server_id);
                CREATE INDEX IF NOT EXISTS idx_inspection_server ON inspection_run(server_id, started_at DESC);
                CREATE INDEX IF NOT EXISTS idx_event_status ON event(status, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_chunk_document ON knowledge_chunk(document_id, chunk_index);
                CREATE INDEX IF NOT EXISTS idx_network_plan_updated ON network_plan(updated_at DESC);
            """)
            self._purge_k8s_data()
            self._conn.commit()

    def _purge_k8s_data(self) -> None:
        """Remove legacy Kubernetes records during the one-way schema cleanup."""
        # This cleanup runs in one transaction after schema creation. A failure
        # rolls back all deletes/drops, leaving the user's existing records intact.
        self._conn.execute("BEGIN")
        try:
            self._conn.execute(
                "DELETE FROM knowledge_fts WHERE CAST(chunk_id AS INTEGER) IN "
                "(SELECT c.id FROM knowledge_chunk c JOIN knowledge_document d ON d.id=c.document_id "
                "WHERE lower(d.source_type) IN ('k8s','kubernetes'))"
            )
            self._conn.execute(
                "DELETE FROM knowledge_document WHERE lower(source_type) IN ('k8s','kubernetes')"
            )
            self._conn.execute(
                "DELETE FROM event WHERE lower(source_type) IN ('k8s','kubernetes')"
            )
            self._conn.execute(
                "DELETE FROM diagnostic_run WHERE plan_id IN "
                "(SELECT id FROM diagnostic_plan WHERE lower(target_type) IN ('k8s','kubernetes'))"
            )
            self._conn.execute(
                "DELETE FROM diagnostic_plan WHERE lower(target_type) IN ('k8s','kubernetes')"
            )
            self._conn.execute("DELETE FROM credential WHERE lower(kind)='kubeconfig'")
            self._conn.execute("DROP TABLE IF EXISTS cluster_profile")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]

    def query_one(self, sql: str, params: tuple = ()) -> Optional[dict[str, Any]]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def executescript(self, sql: str) -> None:
        with self._lock:
            self._conn.executescript(sql)
            self._conn.commit()

    # credentials
    def list_credentials(self) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT id,name,kind,metadata_json,created_at,updated_at,last_used_at FROM credential ORDER BY name"
        )
        for row in rows:
            row["metadata"] = _loads(row.pop("metadata_json"), {})
            row["masked"] = "••••••"
        return rows

    def create_credential(self, name: str, kind: str, secret: str, metadata: dict) -> dict[str, Any]:
        now = utc_now()
        cid = self.execute(
            "INSERT INTO credential(name,kind,secret_blob,metadata_json,created_at,updated_at) VALUES(?,?,?,?,?,?)",
            (name.strip(), kind, protect_secret(secret), json.dumps(metadata, ensure_ascii=False), now, now),
        )
        return next(item for item in self.list_credentials() if item["id"] == cid)

    def update_credential(self, credential_id: int, name: str, kind: str, secret: str | None,
                          metadata: dict) -> dict[str, Any]:
        current = self.query_one("SELECT id FROM credential WHERE id=?", (credential_id,))
        if not current:
            raise ValueError("凭据不存在")
        fields = "name=?,kind=?,metadata_json=?,updated_at=?"
        params: list[Any] = [name.strip(), kind, json.dumps(metadata, ensure_ascii=False), utc_now()]
        if secret is not None:
            fields += ",secret_blob=?"
            params.append(protect_secret(secret))
        params.append(credential_id)
        self.execute(f"UPDATE credential SET {fields} WHERE id=?", tuple(params))
        return next(item for item in self.list_credentials() if item["id"] == credential_id)

    def get_secret(self, credential_id: int | None) -> str:
        if not credential_id:
            return ""
        row = self.query_one("SELECT secret_blob FROM credential WHERE id=?", (credential_id,))
        if not row:
            raise ValueError("凭据不存在")
        self.execute("UPDATE credential SET last_used_at=? WHERE id=?", (utc_now(), credential_id))
        return unprotect_secret(row["secret_blob"])

    # servers / connections
    def list_servers(self) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM server_profile ORDER BY name")
        for row in rows:
            row["tags"] = _loads(row.pop("tags_json"), [])
            row["connections"] = self.list_connections(row["id"])
            last = self.query_one(
                "SELECT id,status,started_at,summary FROM inspection_run WHERE server_id=? ORDER BY id DESC LIMIT 1",
                (row["id"],),
            )
            row["last_inspection"] = last
        return rows

    def get_server(self, server_id: int) -> dict[str, Any] | None:
        return next((item for item in self.list_servers() if item["id"] == server_id), None)

    def save_server(self, data: dict[str, Any], server_id: int | None = None) -> dict[str, Any]:
        now = utc_now()
        values = (
            data["name"].strip(), data["host"].strip(), data.get("os_hint", "linux"),
            data.get("environment", ""), json.dumps(data.get("tags", []), ensure_ascii=False),
            data.get("remark", ""), now,
        )
        if server_id is None:
            server_id = self.execute(
                "INSERT INTO server_profile(name,host,os_hint,environment,tags_json,remark,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?)", values[:-1] + (now, now),
            )
        else:
            if not self.query_one("SELECT id FROM server_profile WHERE id=?", (server_id,)):
                raise ValueError("服务器不存在")
            self.execute(
                "UPDATE server_profile SET name=?,host=?,os_hint=?,environment=?,tags_json=?,remark=?,updated_at=? "
                "WHERE id=?", values + (server_id,),
            )
        return self.get_server(server_id)  # type: ignore[return-value]

    def list_connections(self, server_id: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM connection_profile"
        params: tuple = ()
        if server_id is not None:
            sql += " WHERE server_id=?"
            params = (server_id,)
        rows = self.query(sql + " ORDER BY protocol", params)
        for row in rows:
            row["allow_sudo"] = bool(row["allow_sudo"])
            row["settings"] = _loads(row.pop("settings_json"), {})
        return rows

    def get_connection(self, connection_id: int) -> dict[str, Any] | None:
        return next((item for item in self.list_connections() if item["id"] == connection_id), None)

    def save_connection(self, data: dict[str, Any], connection_id: int | None = None) -> dict[str, Any]:
        now = utc_now()
        values = (
            data["server_id"], data["protocol"], data["host"].strip(), data["port"],
            data.get("username", ""), data.get("domain", ""), data.get("auth_method", "password"),
            data.get("credential_id"), data.get("private_key_id"), data.get("passphrase_id"),
            data.get("jump_connection_id"), int(bool(data.get("allow_sudo"))),
            json.dumps(data.get("settings", {}), ensure_ascii=False),
        )
        if connection_id is None:
            connection_id = self.execute(
                "INSERT INTO connection_profile(server_id,protocol,host,port,username,domain,auth_method,"
                "credential_id,private_key_id,passphrase_id,jump_connection_id,allow_sudo,settings_json,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values + (now, now),
            )
        else:
            self.execute(
                "UPDATE connection_profile SET server_id=?,protocol=?,host=?,port=?,username=?,domain=?,"
                "auth_method=?,credential_id=?,private_key_id=?,passphrase_id=?,jump_connection_id=?,"
                "allow_sudo=?,settings_json=?,updated_at=? WHERE id=?", values + (now, connection_id),
            )
        return self.get_connection(connection_id)  # type: ignore[return-value]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


store = OpsStore()
