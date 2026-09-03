"""Read-only Linux inspection and interactive SSH connection helpers."""

from __future__ import annotations

import hashlib
import asyncio
import io
import json
import socket
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from .infra_store import OpsStore, store, utc_now
from .platform_security import app_data_dir, redact_data, redact_text


INSPECTION_COMMANDS: dict[str, list[tuple[str, str]]] = {
    "basic": [
        ("os", "cat /etc/os-release 2>/dev/null || uname -a"),
        ("kernel", "uname -srmo"),
        ("uptime", "uptime"),
        ("clock", "date -Is; timedatectl show -p NTPSynchronized --value 2>/dev/null"),
        ("cpu", "nproc 2>/dev/null; cat /proc/loadavg 2>/dev/null"),
        ("memory", "free -m 2>/dev/null || cat /proc/meminfo | head -20"),
    ],
    "storage": [
        ("disk", "df -hPT -x tmpfs -x devtmpfs"),
        ("inode", "df -hi -x tmpfs -x devtmpfs"),
        ("mounts", "findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null | head -100"),
    ],
    "network": [
        ("interfaces", "ip -brief address 2>/dev/null || ifconfig -a"),
        ("routes", "ip route show 2>/dev/null || route -n"),
        ("dns", "cat /etc/resolv.conf 2>/dev/null"),
        ("listeners", "ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null"),
        ("firewall", "firewall-cmd --state 2>/dev/null || ufw status 2>/dev/null || nft list ruleset 2>/dev/null | head -80"),
    ],
    "services": [
        ("failed_units", "systemctl --failed --no-pager --plain 2>/dev/null"),
        ("top_cpu", "ps -eo pid,user,comm,%cpu,%mem --sort=-%cpu | head -12"),
        ("top_memory", "ps -eo pid,user,comm,%cpu,%mem --sort=-%mem | head -12"),
    ],
    "security": [
        ("uid0", "awk -F: '$3==0 {print $1}' /etc/passwd"),
        ("ssh_config", "sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication|maxauthtries|allowusers|allowgroups)'"),
        ("failed_logins", "lastb -n 10 2>/dev/null || journalctl -u ssh -u sshd --since '-24 hours' --no-pager 2>/dev/null | grep -i failed | tail -10"),
        ("mac", "getenforce 2>/dev/null || aa-status 2>/dev/null | head -20"),
        ("updates", "command -v dnf >/dev/null && dnf -q check-update --security 2>/dev/null | head -40 || command -v apt >/dev/null && apt list --upgradable 2>/dev/null | head -40"),
    ],
    "containers": [
        ("docker_version", "docker version --format '{{.Server.Version}}' 2>/dev/null"),
        ("containers", "docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null | head -100"),
        ("images", "docker images --format '{{.Repository}}:{{.Tag}}\t{{.Size}}' 2>/dev/null | head -100"),
    ],
}


class UnknownHostKey(RuntimeError):
    def __init__(self, host: str, fingerprint: str) -> None:
        super().__init__(f"尚未信任 {host} 的 SSH 主机密钥")
        self.host = host
        self.fingerprint = fingerprint


class ChangedHostKey(RuntimeError):
    pass


def _paramiko():
    try:
        import paramiko
    except ImportError as exc:
        raise RuntimeError("缺少 Paramiko，无法使用 SSH；请重新安装完整依赖") from exc
    return paramiko


def _load_private_key(text: str, passphrase: str):
    paramiko = _paramiko()
    errors = []
    for cls_name in ("Ed25519Key", "ECDSAKey", "RSAKey"):
        cls = getattr(paramiko, cls_name, None)
        if cls is None:
            continue
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase or None)
        except Exception as exc:  # key formats intentionally tried in sequence
            errors.append(str(exc))
    raise RuntimeError("无法识别私钥格式或私钥口令不正确" + (f"：{errors[-1]}" if errors else ""))


def _host_key_name(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def _connect_one(conn: dict[str, Any], ops_store: OpsStore, trust_host_key: bool,
                 sock=None):
    paramiko = _paramiko()
    known_hosts = app_data_dir() / "known_hosts"
    client = paramiko.SSHClient()
    if known_hosts.exists():
        client.load_host_keys(str(known_hosts))

    class Policy(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, target_client, hostname, key):
            fingerprint = hashlib.sha256(key.asbytes()).hexdigest()
            if not trust_host_key:
                raise UnknownHostKey(hostname, fingerprint)
            target_client.get_host_keys().add(_host_key_name(conn["host"], conn["port"]), key.get_name(), key)
            target_client.save_host_keys(str(known_hosts))

    client.set_missing_host_key_policy(Policy())
    auth: dict[str, Any] = {
        "hostname": conn["host"], "port": int(conn["port"]), "username": conn.get("username") or None,
        "timeout": 10, "banner_timeout": 10, "auth_timeout": 12,
        "allow_agent": False, "look_for_keys": False, "sock": sock,
    }
    if conn.get("auth_method") == "key":
        key_text = ops_store.get_secret(conn.get("private_key_id"))
        passphrase = ops_store.get_secret(conn.get("passphrase_id"))
        auth["pkey"] = _load_private_key(key_text, passphrase)
    else:
        auth["password"] = ops_store.get_secret(conn.get("credential_id"))
    try:
        client.connect(**auth)
    except paramiko.BadHostKeyException as exc:
        raise ChangedHostKey(f"SSH 主机密钥发生变化：{exc.hostname}，已阻止连接") from exc
    return client


def connect_ssh(connection_id: int, trust_host_key: bool = False,
                ops_store: OpsStore = store):
    conn = ops_store.get_connection(connection_id)
    if not conn or conn["protocol"] != "ssh":
        raise ValueError("SSH 连接不存在")
    jump_client = None
    sock = None
    if conn.get("jump_connection_id"):
        jump = ops_store.get_connection(int(conn["jump_connection_id"]))
        if not jump or jump["protocol"] != "ssh":
            raise ValueError("跳板机连接不存在")
        jump_client = _connect_one(jump, ops_store, trust_host_key)
        transport = jump_client.get_transport()
        if transport is None:
            jump_client.close()
            raise RuntimeError("跳板机传输通道不可用")
        sock = transport.open_channel(
            "direct-tcpip", (conn["host"], int(conn["port"])), ("127.0.0.1", 0)
        )
    try:
        client = _connect_one(conn, ops_store, trust_host_key, sock=sock)
    except Exception:
        if jump_client:
            jump_client.close()
        raise
    client._packet_lens_jump_client = jump_client  # retained until close
    return client


def close_ssh(client) -> None:
    jump = getattr(client, "_packet_lens_jump_client", None)
    client.close()
    if jump:
        jump.close()


def test_connection(connection_id: int, trust_host_key: bool = False,
                    ops_store: OpsStore = store) -> dict[str, Any]:
    started = time.monotonic()
    try:
        client = connect_ssh(connection_id, trust_host_key, ops_store)
        transport = client.get_transport()
        remote = transport.remote_version if transport else ""
        close_ssh(client)
        return {"ok": True, "latency_ms": round((time.monotonic() - started) * 1000, 1), "server": remote}
    except UnknownHostKey as exc:
        return {"ok": False, "status": "untrusted", "host": exc.host, "fingerprint": exc.fingerprint,
                "message": str(exc)}
    except Exception as exc:
        return {"ok": False, "status": "error", "message": redact_text(str(exc))}


def _diff_snapshots(previous: dict[str, Any] | None, current: dict[str, Any]) -> list[dict[str, str]]:
    if not previous:
        return []
    changes: list[dict[str, str]] = []
    keys = sorted(set(previous) | set(current))
    for key in keys:
        old = json.dumps(previous.get(key), ensure_ascii=False, sort_keys=True)
        new = json.dumps(current.get(key), ensure_ascii=False, sort_keys=True)
        if old != new:
            changes.append({"section": key, "kind": "changed", "summary": f"{key} 输出发生变化"})
    return changes


def run_inspection(server_id: int, profiles: list[str] | None = None, trigger: str = "manual",
                   trust_host_key: bool = False, ops_store: OpsStore = store) -> dict[str, Any]:
    server = ops_store.get_server(server_id)
    if not server:
        raise ValueError("服务器不存在")
    conn = next((item for item in server["connections"] if item["protocol"] == "ssh"), None)
    if not conn:
        raise ValueError("该服务器没有 SSH 连接")
    selected = profiles or ["basic", "storage", "network", "services", "security", "containers"]
    selected = [name for name in selected if name in INSPECTION_COMMANDS]
    started = utc_now()
    run_id = ops_store.execute(
        "INSERT INTO inspection_run(server_id,trigger,status,started_at) VALUES(?,?,?,?)",
        (server_id, trigger, "running", started),
    )
    snapshot: dict[str, Any] = {}
    failures = 0
    client = None
    try:
        client = connect_ssh(conn["id"], trust_host_key, ops_store)
        for profile in selected:
            section: dict[str, Any] = {}
            for key, command in INSPECTION_COMMANDS[profile]:
                actual = f"sudo -n {command}" if conn.get("allow_sudo") else command
                try:
                    _, stdout, stderr = client.exec_command(actual, timeout=20)
                    output = stdout.read(256 * 1024).decode("utf-8", "replace").strip()
                    error = stderr.read(64 * 1024).decode("utf-8", "replace").strip()
                    status = stdout.channel.recv_exit_status()
                    section[key] = {"ok": status == 0, "output": redact_text(output), "error": redact_text(error)}
                    if status != 0 and not output:
                        failures += 1
                except Exception as exc:
                    failures += 1
                    section[key] = {"ok": False, "output": "", "error": redact_text(str(exc))}
            snapshot[profile] = section
        previous_row = ops_store.query_one(
            "SELECT snapshot_json FROM inspection_run WHERE server_id=? AND id<>? AND status IN ('succeeded','partial') "
            "ORDER BY id DESC LIMIT 1", (server_id, run_id),
        )
        previous = json.loads(previous_row["snapshot_json"]) if previous_row else None
        diff = _diff_snapshots(previous, snapshot)
        status = "partial" if failures else "succeeded"
        summary = f"完成 {len(selected)} 类巡检" + (f"，{failures} 项未取得结果" if failures else "，未发现采集错误")
        ops_store.execute(
            "UPDATE inspection_run SET status=?,finished_at=?,snapshot_json=?,diff_json=?,summary=? WHERE id=?",
            (status, utc_now(), json.dumps(redact_data(snapshot), ensure_ascii=False),
             json.dumps(diff, ensure_ascii=False), summary, run_id),
        )
    except Exception as exc:
        ops_store.execute(
            "UPDATE inspection_run SET status='failed',finished_at=?,error=? WHERE id=?",
            (utc_now(), redact_text(str(exc)), run_id),
        )
    finally:
        if client:
            close_ssh(client)
    return inspection_run(run_id, ops_store)


def inspection_run(run_id: int, ops_store: OpsStore = store) -> dict[str, Any]:
    row = ops_store.query_one("SELECT * FROM inspection_run WHERE id=?", (run_id,))
    if not row:
        raise ValueError("巡检记录不存在")
    row["snapshot"] = json.loads(row.pop("snapshot_json") or "{}")
    row["diff"] = json.loads(row.pop("diff_json") or "[]")
    row["favorite"] = bool(row["favorite"])
    return row


def list_inspections(server_id: int | None = None, limit: int = 50,
                     ops_store: OpsStore = store) -> list[dict[str, Any]]:
    sql = "SELECT id,server_id,task_id,trigger,status,started_at,finished_at,summary,error,favorite FROM inspection_run"
    params: list[Any] = []
    if server_id is not None:
        sql += " WHERE server_id=?"
        params.append(server_id)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(limit, 200)))
    rows = ops_store.query(sql, tuple(params))
    for row in rows:
        row["favorite"] = bool(row["favorite"])
    return rows


def list_tasks(ops_store: OpsStore = store) -> list[dict[str, Any]]:
    rows = ops_store.query("SELECT * FROM inspection_task ORDER BY name")
    for row in rows:
        row["profiles"] = json.loads(row.pop("profiles_json") or "[]")
        row["enabled"] = bool(row["enabled"])
    return rows


def save_task(server_id: int, name: str, profiles: list[str], interval_seconds: int,
              enabled: bool, task_id: int | None = None, ops_store: OpsStore = store) -> dict[str, Any]:
    if not ops_store.get_server(server_id):
        raise ValueError("服务器不存在")
    interval = max(300, min(int(interval_seconds), 86400 * 30))
    selected = [item for item in profiles if item in INSPECTION_COMMANDS]
    if not selected:
        raise ValueError("至少选择一个巡检分类")
    now = datetime.now(timezone.utc)
    next_run = (now + timedelta(seconds=interval)).isoformat(timespec="seconds")
    if task_id is None:
        task_id = ops_store.execute(
            "INSERT INTO inspection_task(server_id,name,profiles_json,interval_seconds,enabled,next_run_at,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
            (server_id, name.strip(), json.dumps(selected, ensure_ascii=False), interval, int(enabled),
             next_run, now.isoformat(timespec="seconds"), now.isoformat(timespec="seconds")),
        )
    else:
        ops_store.execute(
            "UPDATE inspection_task SET server_id=?,name=?,profiles_json=?,interval_seconds=?,enabled=?,"
            "next_run_at=?,updated_at=? WHERE id=?",
            (server_id, name.strip(), json.dumps(selected, ensure_ascii=False), interval, int(enabled),
             next_run, now.isoformat(timespec="seconds"), task_id),
        )
    return next(item for item in list_tasks(ops_store) if item["id"] == task_id)


async def scheduler_loop(ops_store: OpsStore = store) -> None:
    running: set[int] = set()
    while True:
        try:
            due = ops_store.query(
                "SELECT * FROM inspection_task WHERE enabled=1 AND next_run_at IS NOT NULL AND next_run_at<=?",
                (utc_now(),),
            )
            for task in due:
                if task["id"] in running:
                    continue
                running.add(task["id"])
                next_run = (datetime.now(timezone.utc) + timedelta(seconds=task["interval_seconds"])).isoformat(timespec="seconds")
                ops_store.execute("UPDATE inspection_task SET next_run_at=? WHERE id=?", (next_run, task["id"]))

                async def execute(item=task):
                    try:
                        result = await asyncio.to_thread(
                            run_inspection, item["server_id"], json.loads(item["profiles_json"]),
                            "scheduled", False, ops_store,
                        )
                        ops_store.execute(
                            "UPDATE inspection_task SET last_run_at=?,updated_at=? WHERE id=?",
                            (result.get("finished_at"), utc_now(), item["id"]),
                        )
                        if result.get("status") != "succeeded":
                            ops_store.execute(
                                "INSERT INTO event(source_type,source_id,severity,title,detail,created_at) "
                                "VALUES(?,?,?,?,?,?)",
                                ("inspection", str(result["id"]), "warning", "服务器巡检存在异常",
                                 result.get("summary") or result.get("error", ""), utc_now()),
                            )
                    finally:
                        running.discard(item["id"])

                asyncio.create_task(execute())
        except Exception:
            pass
        await asyncio.sleep(15)
