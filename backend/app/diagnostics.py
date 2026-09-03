"""Deterministic, read-only network diagnosis plans and execution."""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import urlparse

import httpx

from .infra_store import OpsStore, store, utc_now
from .platform_security import redact_data, redact_text
from .server_ops import test_connection


def _normalize_target(raw: str) -> tuple[str, str, int | None, str | None]:
    value = raw.strip()
    if not value:
        raise ValueError("诊断目标不能为空")
    url = value if "://" in value else None
    parsed = urlparse(url or f"//{value}")
    host = parsed.hostname or value
    if len(host) > 253 or any(ch in host for ch in "\r\n\t /\\"):
        raise ValueError("诊断目标格式无效")
    scheme = parsed.scheme if url else ""
    port = parsed.port
    if url and port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return value, host, port, url


def create_plan(target: str, target_type: str = "temporary", options: dict[str, Any] | None = None,
                ops_store: OpsStore = store) -> dict[str, Any]:
    options = dict(options or {})
    display, host, port, url = _normalize_target(target)
    if options.get("port"):
        port = int(options["port"])
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("端口必须在 1-65535 之间")
    steps = [
        {"id": "dns", "label": "DNS A/AAAA 解析", "request": host},
        {"id": "ping", "label": "Ping 连通性", "request": host},
        {"id": "route", "label": "路由跟踪", "request": host},
    ]
    if port:
        steps.append({"id": "tcp", "label": "TCP 端口连接", "request": f"{host}:{port}"})
    if port == 443 or (url and url.startswith("https://")) or options.get("tls"):
        steps.append({"id": "tls", "label": "TLS 握手与证书", "request": f"{host}:{port or 443}"})
    if url:
        steps.append({"id": "http", "label": "HTTP 状态与响应时间", "request": url})
    server_id = options.get("server_id")
    if server_id:
        server = ops_store.get_server(int(server_id))
        if not server:
            raise ValueError("关联服务器不存在")
        ssh = next((item for item in server["connections"] if item["protocol"] == "ssh"), None)
        if ssh:
            steps.append({"id": "ssh", "label": "SSH 连接验证", "request": server["name"],
                          "connection_id": ssh["id"]})
    now = datetime.now(timezone.utc)
    plan_id = ops_store.execute(
        "INSERT INTO diagnostic_plan(target_type,target,options_json,steps_json,created_at,expires_at) "
        "VALUES(?,?,?,?,?,?)",
        (target_type, display, json.dumps(options, ensure_ascii=False), json.dumps(steps, ensure_ascii=False),
         now.isoformat(timespec="seconds"), (now + timedelta(minutes=15)).isoformat(timespec="seconds")),
    )
    return get_plan(plan_id, ops_store)


def get_plan(plan_id: int, ops_store: OpsStore = store) -> dict[str, Any]:
    row = ops_store.query_one("SELECT * FROM diagnostic_plan WHERE id=?", (plan_id,))
    if not row:
        raise ValueError("诊断计划不存在")
    row["options"] = json.loads(row.pop("options_json") or "{}")
    row["steps"] = json.loads(row.pop("steps_json") or "[]")
    return row


def list_runs(limit: int = 50, ops_store: OpsStore = store) -> list[dict[str, Any]]:
    rows = ops_store.query(
        "SELECT id,plan_id,status,target,started_at,finished_at,summary,favorite FROM diagnostic_run "
        "ORDER BY id DESC LIMIT ?", (max(1, min(limit, 200)),),
    )
    for row in rows:
        row["favorite"] = bool(row["favorite"])
    return rows


def get_run(run_id: int, ops_store: OpsStore = store) -> dict[str, Any]:
    row = ops_store.query_one("SELECT * FROM diagnostic_run WHERE id=?", (run_id,))
    if not row:
        raise ValueError("诊断记录不存在")
    row["timeline"] = json.loads(row.pop("timeline_json") or "[]")
    row["favorite"] = bool(row["favorite"])
    return row


def _timed(step_id: str, label: str, fn: Callable[[], Any]) -> dict[str, Any]:
    started = time.monotonic()
    item = {"step": step_id, "label": label, "started_at": utc_now()}
    try:
        item["result"] = redact_data(fn())
        item["ok"] = bool(item["result"].get("ok", True)) if isinstance(item["result"], dict) else True
    except Exception as exc:
        item["ok"] = False
        item["error"] = redact_text(str(exc))
    item["duration_ms"] = round((time.monotonic() - started) * 1000, 1)
    return item


def _dns(host: str) -> dict[str, Any]:
    rows = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    values = sorted({row[4][0] for row in rows})
    return {"ok": bool(values), "addresses": values}


def _ping(host: str) -> dict[str, Any]:
    cp = subprocess.run(
        ["ping", "-n", "2", "-w", "1000", host], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=8, creationflags=0x08000000,
    )
    return {"ok": cp.returncode == 0, "detail": redact_text((cp.stdout or cp.stderr)[-3000:])}


def _route(host: str) -> dict[str, Any]:
    cp = subprocess.run(
        ["tracert", "-d", "-h", "12", "-w", "800", host], capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=20, creationflags=0x08000000,
    )
    return {"ok": cp.returncode == 0, "detail": redact_text((cp.stdout or cp.stderr)[-6000:])}


def _tcp(host: str, port: int) -> dict[str, Any]:
    started = time.monotonic()
    with socket.create_connection((host, port), timeout=4):
        pass
    return {"ok": True, "endpoint": f"{host}:{port}",
            "latency_ms": round((time.monotonic() - started) * 1000, 1)}


def _tls(host: str, port: int) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
            return {
                "ok": True, "protocol": tls.version(), "cipher": (tls.cipher() or [""])[0],
                "subject": dict(item[0] for item in cert.get("subject", [])),
                "issuer": dict(item[0] for item in cert.get("issuer", [])),
                "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
            }


def _http(url: str) -> dict[str, Any]:
    started = time.monotonic()
    with httpx.Client(timeout=8, follow_redirects=True, verify=True) as client:
        response = client.get(url, headers={"User-Agent": "PacketLens/0.7"})
    return {"ok": response.status_code < 500, "status_code": response.status_code,
            "final_url": str(response.url), "latency_ms": round((time.monotonic() - started) * 1000, 1),
            "server": response.headers.get("server", "")}


def run_plan(plan_id: int, emit: Callable[[dict[str, Any]], None] | None = None,
             ops_store: OpsStore = store) -> dict[str, Any]:
    plan = get_plan(plan_id, ops_store)
    if datetime.fromisoformat(plan["expires_at"]) < datetime.now(timezone.utc):
        raise ValueError("诊断计划已过期，请重新生成")
    ops_store.execute("UPDATE diagnostic_plan SET approved_at=? WHERE id=?", (utc_now(), plan_id))
    run_id = ops_store.execute(
        "INSERT INTO diagnostic_run(plan_id,status,target,started_at) VALUES(?,?,?,?)",
        (plan_id, "running", plan["target"], utc_now()),
    )
    _, host, port, url = _normalize_target(plan["target"])
    timeline: list[dict[str, Any]] = []
    for index, step in enumerate(plan["steps"]):
        step_id = step["id"]
        if step_id == "dns": fn = lambda: _dns(host)
        elif step_id == "ping": fn = lambda: _ping(host)
        elif step_id == "route": fn = lambda: _route(host)
        elif step_id == "tcp": fn = lambda: _tcp(host, port or int(plan["options"].get("port") or 80))
        elif step_id == "tls": fn = lambda: _tls(host, port or 443)
        elif step_id == "http": fn = lambda: _http(url or plan["target"])
        elif step_id == "ssh": fn = lambda: test_connection(int(step["connection_id"]), False, ops_store)
        else: continue
        item = _timed(step_id, step["label"], fn)
        timeline.append(item)
        if emit:
            emit({"type": "progress", "done": index + 1, "total": len(plan["steps"]), "step": item})
        ops_store.execute(
            "UPDATE diagnostic_run SET timeline_json=? WHERE id=?",
            (json.dumps(timeline, ensure_ascii=False), run_id),
        )
    ok_count = sum(1 for item in timeline if item.get("ok"))
    failed_count = len(timeline) - ok_count
    status = "succeeded" if failed_count == 0 else "failed" if ok_count == 0 else "partial"
    failed_labels = [item["label"] for item in timeline if not item.get("ok")]
    summary = f"{ok_count}/{len(timeline)} 个诊断步骤成功"
    if failed_labels:
        summary += f"；异常层级：{'、'.join(failed_labels)}"
        ops_store.execute(
            "INSERT INTO event(source_type,source_id,severity,title,detail,created_at) VALUES(?,?,?,?,?,?)",
            ("diagnostic", str(run_id), "warning" if status == "partial" else "error",
             f"诊断发现异常：{plan['target']}", summary, utc_now()),
        )
    ops_store.execute(
        "UPDATE diagnostic_run SET status=?,finished_at=?,timeline_json=?,summary=? WHERE id=?",
        (status, utc_now(), json.dumps(timeline, ensure_ascii=False), summary, run_id),
    )
    return get_run(run_id, ops_store)

