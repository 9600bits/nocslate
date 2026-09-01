from __future__ import annotations

import asyncio
import locale
import os
import re
import socket
import ssl
import subprocess
import time
from collections.abc import Callable
from functools import lru_cache
from typing import AsyncIterator

import certifi
import httpx
from pydantic import BaseModel, Field


MAX_TARGETS = 512
MAX_TCP_TASKS = 8192

DEFAULT_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
    8080, 8443, 9090, 27017,
]


class ProbeRunIn(BaseModel):
    type: str = Field(pattern="^(ping|http|tcp)$")
    targets: list[str] = Field(min_length=1, max_length=MAX_TARGETS)
    ping_count: int = Field(default=4, ge=1, le=65536)
    ping_timeout_ms: int = Field(default=1000, ge=100, le=10000)
    http_method: str = Field(default="GET", pattern="^(GET|HEAD)$")
    follow_redirects: bool = True
    verify_tls: bool = True
    http_timeout_s: float = Field(default=10, ge=1, le=30)
    ports: list[int] = []
    concurrency: int = Field(default=64, ge=1, le=256)
    tcp_concurrency: int = Field(default=128, ge=1, le=512)


class ProbeAnalyzeIn(BaseModel):
    probe_type: str = Field(pattern="^(ping|http|tcp)$")
    summary: dict = {}
    results: list[dict] = []


def clean_targets(targets: list[str]) -> list[str]:
    seen = set()
    cleaned = []
    for raw in targets:
        value = str(raw).strip().rstrip(",")
        if not value or value.lower() in {"http://", "https://"}:
            continue
        if value not in seen:
            seen.add(value)
            cleaned.append(value)
        if len(cleaned) >= MAX_TARGETS:
            break
    return cleaned


def normalize_ports(ports: list[int]) -> list[int]:
    unique = sorted({int(p) for p in ports if 1 <= int(p) <= 65535})
    return unique or list(DEFAULT_TCP_PORTS)


def _normalize_http_target(target: str) -> str:
    value = target.strip()
    if not re.match(r"^https?://", value, re.IGNORECASE):
        value = "http://" + value
    return value


def parse_ping_output(text: str, count: int) -> dict:
    latencies: list[int] = []
    replies = 0
    for line in text.splitlines():
        if re.search(r"TTL[=:]\s*\d+", line, re.IGNORECASE):
            replies += 1
        match = re.search(r"(?:time|时间)\s*[=<]\s*(\d+)\s*ms", line, re.IGNORECASE)
        if match:
            latencies.append(int(match.group(1)))

    avg_match = re.search(r"(?:Average|平均)\s*=\s*(\d+)\s*ms", text, re.IGNORECASE)
    average = int(avg_match.group(1)) if avg_match else (
        round(sum(latencies) / len(latencies), 1) if latencies else None
    )
    loss = max(0, count - replies)
    status = "reachable" if replies > 0 else "timeout"
    if replies == 0 and re.search(r"unreachable|无法访问|不能访问", text, re.IGNORECASE):
        status = "unreachable"
    return {
        "replies": replies,
        "loss": loss,
        "avg_ms": average,
        "status": status,
    }


def _ping_latency(line: str) -> float | None:
    match = re.search(
        r"(?:time|时间)\s*([=<])?\s*(\d+(?:\.\d+)?)\s*ms",
        line, re.IGNORECASE,
    )
    if not match:
        return None
    # Windows reports sub-millisecond replies as time<1ms; statistics use 0ms.
    return 0.0 if match.group(1) == "<" else float(match.group(2))


def _is_ping_reply(line: str) -> bool:
    return bool(re.search(r"TTL[=:]\s*\d+", line, re.IGNORECASE))


def _is_ping_timeout(line: str) -> bool:
    return bool(re.search(r"Request timed out|请求超时", line, re.IGNORECASE))


def _decode_process_output(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode(locale.getpreferredencoding(False), errors="replace")


def _classify_http_status(status: int) -> tuple[bool, str]:
    if 200 <= status < 300:
        return True, "ok"
    if 300 <= status < 400:
        return True, "redirect"
    if 400 <= status < 500:
        return False, "client_error"
    return False, "server_error"


async def _run_ping(target: str, count: int, timeout_ms: int,
                    on_update: Callable[[dict], None] | None = None) -> dict:
    command = [
        "ping", "-n", str(count), "-w", str(timeout_ms), target,
    ] if os.name == "nt" else ["ping", "-c", str(count), "-W", str(max(1, timeout_ms // 1000)), target]
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    process_timeout = (count * timeout_ms / 1000) + 4
    started = time.perf_counter()
    proc = None
    replies = 0
    timeouts = 0
    latencies: list[float] = []
    unreachable = False
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            creationflags=creation_flags,
        )
        while True:
            line_bytes = await asyncio.wait_for(proc.stdout.readline(), timeout=process_timeout)
            if not line_bytes:
                break
            line = _decode_process_output(line_bytes)
            latency = _ping_latency(line)
            if _is_ping_reply(line):
                replies += 1
                if latency is not None:
                    latencies.append(latency)
            elif _is_ping_timeout(line):
                timeouts += 1
            elif re.search(r"unreachable|无法访问|不能访问", line, re.IGNORECASE):
                unreachable = True

            if on_update and (latency is not None or _is_ping_timeout(line)):
                attempts = replies + timeouts
                average = round(sum(latencies) / len(latencies), 1) if latencies else None
                loss = attempts - replies
                on_update({
                    "type": "ping_update",
                    "target": target,
                    "count": count,
                    "sequence": attempts,
                    "latency_ms": latency,
                    "replies": replies,
                    "loss": loss,
                    "avg_ms": average,
                    "detail": (
                        f"{attempts}/{count} 已探测，最新 "
                        f"{latency if latency is not None else '-'}ms，"
                        f"平均 {average if average is not None else '-'}ms，"
                        f"丢包 {loss}"
                    ),
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
                })

        try:
            await asyncio.wait_for(proc.wait(), timeout=4)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

        elapsed = round((time.perf_counter() - started) * 1000, 1)
        average = round(sum(latencies) / len(latencies), 1) if latencies else None
        status = "reachable" if replies > 0 else ("unreachable" if unreachable else "timeout")
        loss = max(0, count - replies)
        return {
            "type": "ping",
            "target": target,
            "ok": replies > 0,
            "status": status,
            "detail": (
                f"{replies}/{count} 应答，"
                f"平均 {average if average is not None else '-'}ms，"
                f"丢包 {loss}"
            ),
            "replies": replies,
            "sent": count,
            "loss": loss,
            "avg_ms": average,
            "elapsed_ms": elapsed,
        }
    except asyncio.TimeoutError:
        return {
            "type": "ping", "target": target, "ok": False, "status": "timeout",
            "detail": "Ping 超时", "replies": 0, "sent": count,
            "loss": count, "avg_ms": None,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }
    except FileNotFoundError:
        return {
            "type": "ping", "target": target, "ok": False, "status": "error",
            "detail": "系统 ping 命令不可用", "replies": 0, "sent": count,
            "loss": count, "avg_ms": None,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }
    except OSError as exc:
        return {
            "type": "ping", "target": target, "ok": False, "status": "error",
            "detail": f"启动 ping 失败: {exc}", "replies": 0, "sent": count,
            "loss": count, "avg_ms": None,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }
    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
            await proc.wait()


async def probe_ping(target: str, count: int, timeout_ms: int) -> dict:
    return await _run_ping(target, count, timeout_ms)


def _make_http_client(follow_redirects: bool, verify_tls: bool,
                      timeout_s: float, concurrency: int = 1) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        follow_redirects=follow_redirects,
        verify=_http_ssl_context(verify_tls),
        timeout=httpx.Timeout(timeout_s),
        limits=httpx.Limits(
            max_connections=concurrency,
            max_keepalive_connections=min(32, concurrency),
        ),
    )


@lru_cache(maxsize=2)
def _http_ssl_context(verify_tls: bool) -> ssl.SSLContext | bool:
    if not verify_tls:
        return False
    return ssl.create_default_context(cafile=certifi.where())


async def probe_http(target: str, method: str, follow_redirects: bool,
                     verify_tls: bool, timeout_s: float,
                     client: httpx.AsyncClient | None = None) -> dict:
    url = _normalize_http_target(target)
    owned_client = client is None
    if owned_client:
        client = _make_http_client(follow_redirects, verify_tls, timeout_s)
    started = time.perf_counter()
    try:
        try:
            response = await client.request(method, url)
        finally:
            if owned_client:
                await client.aclose()
        elapsed = round((time.perf_counter() - started) * 1000, 1)
        ok, status = _classify_http_status(response.status_code)
        return {
            "type": "http",
            "target": url,
            "ok": ok,
            "status": str(response.status_code),
            "category": status,
            "reason": response.reason_phrase,
            "final_url": str(response.url),
            "elapsed_ms": elapsed,
            "content_type": response.headers.get("content-type", ""),
            "content_length": response.headers.get("content-length", ""),
            "detail": f"HTTP {response.status_code} {response.reason_phrase}".rstrip(),
        }
    except httpx.TimeoutException:
        return _http_error(url, started, "timeout", "请求超时")
    except httpx.TooManyRedirects as exc:
        return _http_error(url, started, "error", f"重定向过多: {exc}")
    except httpx.HTTPStatusError:
        return _http_error(url, started, "error", "HTTP 协议错误")
    except httpx.ConnectError as exc:
        return _http_error(url, started, "unreachable", f"连接失败: {exc}")
    except httpx.SSLError as exc:
        return _http_error(url, started, "tls_error", f"TLS 校验失败: {exc}")
    except httpx.HTTPError as exc:
        return _http_error(url, started, "error", f"HTTP 请求失败: {exc}")


def _http_error(url: str, started: float, status: str, detail: str) -> dict:
    return {
        "type": "http", "target": url, "ok": False, "status": status,
        "category": status, "reason": "", "final_url": url,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        "content_type": "", "content_length": "", "detail": detail,
    }


def _tcp_error(port_target: tuple[str, int], started: float, status: str, detail: str) -> dict:
    host, port = port_target
    return {
        "type": "tcp", "target": host, "port": port,
        "endpoint": f"{host}:{port}", "ok": status == "open",
        "status": status, "detail": detail,
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
    }


async def probe_tcp(host: str, port: int, timeout_s: float = 2.0) -> dict:
    started = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout_s
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {
            "type": "tcp", "target": host, "port": port,
            "endpoint": f"{host}:{port}", "ok": True, "status": "open",
            "detail": "端口开放", "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }
    except asyncio.TimeoutError:
        return _tcp_error((host, port), started, "timeout", "连接超时或被过滤")
    except ConnectionRefusedError:
        return _tcp_error((host, port), started, "closed", "连接被拒绝")
    except socket.gaierror as exc:
        return _tcp_error((host, port), started, "error", f"域名解析失败: {exc}")
    except OSError as exc:
        lowered = str(exc).lower()
        if "unreachable" in lowered or "no route" in lowered or "无法访问" in str(exc):
            return _tcp_error((host, port), started, "unreachable", f"目标不可达: {exc}")
        return _tcp_error((host, port), started, "error", f"连接错误: {exc}")


async def _ping_worker(target: str, body: ProbeRunIn, semaphore: asyncio.Semaphore,
                       queue: asyncio.Queue) -> None:
    async with semaphore:
        def emit(event: dict) -> None:
            queue.put_nowait(event)

        try:
            result = await _run_ping(target, body.ping_count, body.ping_timeout_ms, emit)
        except Exception as exc:
            result = {
                "type": "ping", "target": target, "ok": False, "status": "error",
                "detail": f"Ping 执行失败: {exc}", "replies": 0,
                "sent": body.ping_count, "loss": body.ping_count, "avg_ms": None,
            }
        await queue.put({"type": "result", "result": result})


async def _http_worker(target: str, body: ProbeRunIn, semaphore: asyncio.Semaphore,
                       client: httpx.AsyncClient) -> dict:
    async with semaphore:
        return await probe_http(
            target, body.http_method, body.follow_redirects,
            body.verify_tls, body.http_timeout_s, client,
        )


async def _tcp_worker(host: str, port: int, body: ProbeRunIn,
                      semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        return await probe_tcp(host, port, timeout_s=min(10.0, max(1.0, body.http_timeout_s)))


async def run_probe(body: ProbeRunIn) -> AsyncIterator[dict]:
    targets = clean_targets(body.targets)
    if not targets:
        yield {"type": "error", "message": "没有有效目标"}
        return
    if body.type == "ping":
        semaphore = asyncio.Semaphore(body.concurrency)
        queue: asyncio.Queue = asyncio.Queue()
        total = len(targets)
        started = time.perf_counter()
        yield {"type": "start", "probe_type": body.type, "total": total}
        tasks = [
            asyncio.create_task(_ping_worker(target, body, semaphore, queue))
            for target in targets
        ]
        statuses: dict[str, int] = {}
        completed = 0
        try:
            while completed < total:
                event = await queue.get()
                if event["type"] == "ping_update":
                    yield event
                    continue
                result = event["result"]
                completed += 1
                status = str(result.get("category") or result.get("status", "error"))
                statuses[status] = statuses.get(status, 0) + 1
                yield {
                    "type": "result", "result": result,
                    "done": completed, "total": total,
                }
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        yield {
            "type": "summary",
            "probe_type": body.type,
            "total": total,
            "completed": completed,
            "statuses": statuses,
            "ok_count": sum(v for k, v in statuses.items() if k in {"reachable", "ok", "redirect", "open"}),
            "error_count": sum(v for k, v in statuses.items() if k not in {"reachable", "ok", "redirect", "open"}),
            "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        }
        return

    if body.type == "tcp":
        ports = normalize_ports(body.ports)
        if len(targets) * len(ports) > MAX_TCP_TASKS:
            yield {"type": "error", "message": "目标端口组合超过 8192，请减少目标或端口"}
            return
        semaphore = asyncio.Semaphore(body.tcp_concurrency)
        tasks = [
            _tcp_worker(host, port, body, semaphore)
            for host in targets for port in ports
        ]
    elif body.type == "http":
        semaphore = asyncio.Semaphore(body.concurrency)
        client = _make_http_client(
            body.follow_redirects, body.verify_tls, body.http_timeout_s, body.concurrency,
        )
        tasks = [
            _http_worker(target, body, semaphore, client)
            for target in targets
        ]
    else:
        semaphore = asyncio.Semaphore(body.concurrency)
        tasks = [
            _ping_worker(target, body, semaphore)
            for target in targets
        ]

    total = len(tasks)
    started = time.perf_counter()
    yield {"type": "start", "probe_type": body.type, "total": total}

    statuses: dict[str, int] = {}
    completed = 0
    try:
        for awaitable in asyncio.as_completed(tasks):
            result = await awaitable
            completed += 1
            status = str(result.get("category") or result.get("status", "error"))
            statuses[status] = statuses.get(status, 0) + 1
            yield {"type": "result", "result": result, "done": completed, "total": total}
    finally:
        if body.type == "http":
            await client.aclose()

    yield {
        "type": "summary",
        "probe_type": body.type,
        "total": total,
        "completed": completed,
        "statuses": statuses,
        "ok_count": sum(v for k, v in statuses.items() if k in {"reachable", "ok", "redirect", "open"}),
        "error_count": sum(v for k, v in statuses.items() if k not in {"reachable", "ok", "redirect", "open"}),
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
    }
