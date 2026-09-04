"""Scheduled probes and persistent execution history."""

from __future__ import annotations

import asyncio
import json
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

from . import probes
from .platform_security import app_data_dir

MAX_SAVED_RESULTS = 1000


class MonitorTaskIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    probe_type: Literal["ping", "http", "tcp"]
    targets: list[str] = Field(min_length=1, max_length=probes.MAX_TARGETS)
    ports: list[int] = []
    interval_seconds: int = Field(default=300, ge=30, le=86400)
    enabled: bool = True
    ping_count: int = Field(default=4, ge=1, le=100)
    ping_timeout_ms: int = Field(default=1000, ge=100, le=10000)
    http_method: str = Field(default="GET", pattern="^(GET|HEAD)$")
    follow_redirects: bool = True
    verify_tls: bool = True
    http_timeout_s: float = Field(default=10, ge=1, le=30)
    concurrency: int = Field(default=64, ge=1, le=256)
    tcp_concurrency: int = Field(default=128, ge=1, le=512)


class MonitorUpdateIn(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=80)
    interval_seconds: Optional[int] = Field(default=None, ge=30, le=86400)
    enabled: Optional[bool] = None


def db_path() -> Path:
    if getattr(sys, "frozen", False):
        target = app_data_dir() / "monitor.db"
        target.parent.mkdir(parents=True, exist_ok=True)
        legacy = Path(sys.executable).resolve().parent / "monitor.db"
        if not target.exists() and legacy.exists() and legacy.resolve() != target.resolve():
            source = sqlite3.connect(str(legacy))
            destination = sqlite3.connect(str(target))
            try:
                source.backup(destination)
            finally:
                destination.close()
                source.close()
        return target
    return Path(__file__).resolve().parent.parent / "monitor.db"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


class MonitorStore:
    """Small SQLite persistence layer for periodic probe tasks."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._conn = _connect(db_path())
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS monitor_task (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    probe_type TEXT NOT NULL,
                    targets TEXT NOT NULL,
                    ports TEXT NOT NULL DEFAULT '[]',
                    interval_seconds INTEGER NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    settings TEXT NOT NULL DEFAULT '{}',
                    last_run_at TEXT,
                    next_run_at TEXT,
                    last_status TEXT NOT NULL DEFAULT '未运行',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS monitor_run (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id INTEGER NOT NULL REFERENCES monitor_task(id) ON DELETE CASCADE,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    trigger TEXT NOT NULL,
                    status TEXT NOT NULL,
                    summary TEXT NOT NULL DEFAULT '{}',
                    results TEXT NOT NULL DEFAULT '[]',
                    ok_count INTEGER NOT NULL DEFAULT 0,
                    error_count INTEGER NOT NULL DEFAULT 0,
                    total_count INTEGER NOT NULL DEFAULT 0,
                    duration_ms REAL NOT NULL DEFAULT 0,
                    result_count INTEGER NOT NULL DEFAULT 0,
                    truncated INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_monitor_run_task ON monitor_run(task_id, started_at DESC);
            """)
            self._conn.commit()

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

    def execute_rowcount(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return int(cur.rowcount or 0)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _connect(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _task_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        **row,
        "targets": json.loads(row.get("targets") or "[]"),
        "ports": json.loads(row.get("ports") or "[]"),
        "settings": json.loads(row.get("settings") or "{}"),
        "enabled": bool(row.get("enabled")),
    }


def _run_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        **row,
        "summary": json.loads(row.get("summary") or "{}"),
        "results": json.loads(row.get("results") or "[]"),
        "truncated": bool(row.get("truncated")),
    }


class MonitorService:
    def __init__(self, store: MonitorStore) -> None:
        self.store = store

    def list_tasks(self) -> list[dict[str, Any]]:
        rows = self.store.query("SELECT * FROM monitor_task ORDER BY name")
        return [_task_row(row) for row in rows]

    def get_task(self, task_id: int) -> Optional[dict[str, Any]]:
        row = self.store.query_one("SELECT * FROM monitor_task WHERE id=?", (task_id,))
        return _task_row(row) if row else None

    def create_task(self, data: MonitorTaskIn) -> dict[str, Any]:
        targets = probes.clean_targets(data.targets)
        if not targets:
            raise ValueError("没有有效目标")
        now = utc_now()
        next_run = (datetime.now(timezone.utc) + timedelta(seconds=data.interval_seconds)).isoformat(timespec="microseconds")
        settings = data.model_dump(exclude={"name", "probe_type", "targets", "ports", "interval_seconds", "enabled"})
        task_id = self.store.execute(
            "INSERT INTO monitor_task(name,probe_type,targets,ports,interval_seconds,enabled,settings,"
            "next_run_at,last_status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                data.name.strip(), data.probe_type, json.dumps(targets, ensure_ascii=False),
                json.dumps(probes.normalize_ports(data.ports) if data.probe_type == "tcp" else []),
                data.interval_seconds, int(data.enabled), json.dumps(settings, ensure_ascii=False),
                next_run, "未运行", now,
            ),
        )
        return self.get_task(task_id)  # type: ignore[return-value]

    def update_task(self, task_id: int, data: MonitorUpdateIn) -> dict[str, Any]:
        task = self.get_task(task_id)
        if task is None:
            raise ValueError("监控任务不存在")
        fields: list[str] = []
        params: list[Any] = []
        if data.name is not None:
            fields.append("name=?")
            params.append(data.name.strip())
        if data.interval_seconds is not None:
            fields.append("interval_seconds=?")
            params.append(data.interval_seconds)
            base = datetime.now(timezone.utc)
            fields.append("next_run_at=?")
            params.append((base + timedelta(seconds=data.interval_seconds)).isoformat(timespec="microseconds"))
        if data.enabled is not None:
            fields.append("enabled=?")
            params.append(int(data.enabled))
        if fields:
            params.append(task_id)
            self.store.execute(f"UPDATE monitor_task SET {', '.join(fields)} WHERE id=?", tuple(params))
        return self.get_task(task_id)  # type: ignore[return-value]

    def delete_task(self, task_id: int) -> None:
        self.store.execute("DELETE FROM monitor_task WHERE id=?", (task_id,))

    def due_tasks(self) -> list[dict[str, Any]]:
        rows = self.store.query(
            "SELECT * FROM monitor_task WHERE enabled=1 AND next_run_at <= ? ORDER BY next_run_at",
            (utc_now(),),
        )
        return [_task_row(row) for row in rows]

    def claim_due(self, task_id: int, next_run_at: str) -> bool:
        task = self.get_task(task_id)
        if task is None or task.get("next_run_at") != next_run_at:
            return False
        next_run = (
            datetime.now(timezone.utc) + timedelta(seconds=task["interval_seconds"])
        ).isoformat(timespec="microseconds")
        rowcount = self.store.execute_rowcount(
            "UPDATE monitor_task SET next_run_at=? WHERE id=? AND next_run_at=? AND enabled=1",
            (next_run, task_id, next_run_at),
        )
        return rowcount == 1

    def list_runs(self, task_id: int, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.store.query(
            "SELECT * FROM monitor_run WHERE task_id=? ORDER BY id DESC LIMIT ?",
            (task_id, min(100, max(1, limit))),
        )
        return [_run_row(row) for row in rows]

    def get_run(self, run_id: int) -> Optional[dict[str, Any]]:
        row = self.store.query_one("SELECT * FROM monitor_run WHERE id=?", (run_id,))
        return _run_row(row) if row else None

    async def run_task(self, task_id: int, trigger: str = "manual") -> dict[str, Any]:
        task = self.get_task(task_id)
        if task is None:
            raise ValueError("监控任务不存在")
        started = utc_now()
        settings = task.get("settings") or {}
        body = probes.ProbeRunIn(
            type=task["probe_type"], targets=task["targets"], ports=task["ports"],
            ping_count=settings.get("ping_count", 4),
            ping_timeout_ms=settings.get("ping_timeout_ms", 1000),
            http_method=settings.get("http_method", "GET"),
            follow_redirects=settings.get("follow_redirects", True),
            verify_tls=settings.get("verify_tls", True),
            http_timeout_s=settings.get("http_timeout_s", 10),
            concurrency=settings.get("concurrency", 64),
            tcp_concurrency=settings.get("tcp_concurrency", 128),
        )
        results: list[dict[str, Any]] = []
        summary: dict[str, Any] = {}
        status = "completed"
        try:
            async for event in probes.run_probe(body):
                if event.get("type") == "result":
                    results.append(event["result"])
                elif event.get("type") == "summary":
                    summary = event
                elif event.get("type") == "error":
                    status = "error"
                    summary = {"error": event.get("message", "探测失败")}
        except Exception as exc:  # noqa: BLE001
            status = "error"
            summary = {"error": str(exc)}

        ok_count = int(summary.get("ok_count", 0))
        error_count = int(summary.get("error_count", 0))
        total_count = int(summary.get("total", len(results)))
        duration_ms = float(summary.get("duration_ms", 0))
        truncated = max(0, len(results) - MAX_SAVED_RESULTS)
        run_id = self.store.execute(
            "INSERT INTO monitor_run(task_id,started_at,finished_at,trigger,status,summary,results,"
            "ok_count,error_count,total_count,duration_ms,result_count,truncated) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                task_id, started, utc_now(), trigger, status,
                json.dumps(summary, ensure_ascii=False),
                json.dumps(results[:MAX_SAVED_RESULTS], ensure_ascii=False),
                ok_count, error_count, total_count, duration_ms,
                min(len(results), MAX_SAVED_RESULTS), int(truncated > 0),
            ),
        )
        display = "异常" if error_count or status == "error" else "正常"
        next_run = (datetime.now(timezone.utc) + timedelta(seconds=task["interval_seconds"])).isoformat(timespec="microseconds")
        self.store.execute(
            "UPDATE monitor_task SET last_run_at=?, next_run_at=?, last_status=? WHERE id=?",
            (started, next_run, display, task_id),
        )
        run = self.get_run(run_id)  # type: ignore[arg-type]
        return run  # type: ignore[return-value]

    def diff_latest(self, task_id: int) -> dict[str, Any]:
        runs = self.list_runs(task_id, 2)
        if not runs:
            raise ValueError("还没有可对比的运行历史")
        if len(runs) == 1:
            return {"has_previous": False, "current": runs[0], "previous": None, "changes": []}
        current, previous = runs[0], runs[1]
        return {
            "has_previous": True,
            "current": current,
            "previous": previous,
            "changes": self._build_diff(task_id, previous["results"], current["results"]),
        }

    def _build_diff(self, task_id: int, old: list[dict[str, Any]], new: list[dict[str, Any]]) -> list[dict[str, Any]]:
        task = self.get_task(task_id)
        kind = task.get("probe_type") if task else "ping"
        changes: list[dict[str, Any]] = []
        if kind == "tcp":
            def key(item: dict[str, Any]) -> str:
                return item.get("endpoint") or f"{item.get('target')}:{item.get('port')}"

            old_map = {key(item): item for item in old}
            new_map = {key(item): item for item in new}
            for endpoint in sorted(set(old_map) | set(new_map)):
                before, after = old_map.get(endpoint), new_map.get(endpoint)
                old_open = bool(before and before.get("status") == "open")
                new_open = bool(after and after.get("status") == "open")
                if old_open != new_open:
                    changes.append({
                        "key": endpoint, "kind": "opened" if new_open else "closed",
                        "old": before, "new": after,
                    })
        else:
            def key(item: dict[str, Any]) -> str:
                return str(item.get("target", ""))

            old_map = {key(item): item for item in old}
            new_map = {key(item): item for item in new}
            for target in sorted(set(old_map) | set(new_map)):
                before, after = old_map.get(target), new_map.get(target)
                old_status = before.get("category") or before.get("status") if before else None
                new_status = after.get("category") or after.get("status") if after else None
                if old_status != new_status:
                    changes.append({
                        "key": target, "kind": "status",
                        "old": before, "new": after,
                    })
                elif kind == "ping":
                    old_avg, new_avg = before and before.get("avg_ms"), after and after.get("avg_ms")
                    if old_avg is not None and new_avg is not None and abs(float(new_avg) - float(old_avg)) >= 50:
                        changes.append({
                            "key": target, "kind": "latency", "old": before, "new": after,
                        })
        return changes


store = MonitorStore()
service = MonitorService(store)
running_tasks: set[asyncio.Task] = set()


async def scheduler_loop(service: MonitorService) -> None:
    while True:
        try:
            due = await asyncio.to_thread(service.due_tasks)
            for task in due:
                if await asyncio.to_thread(service.claim_due, task["id"], task["next_run_at"]):
                    scheduled = asyncio.create_task(service.run_task(task["id"], "scheduled"))
                    running_tasks.add(scheduled)
                    scheduled.add_done_callback(running_tasks.discard)
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(2)
