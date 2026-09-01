from __future__ import annotations

import asyncio
import ssl
import time
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Callable

import httpx
from cryptography import x509
from pydantic import BaseModel, Field

from . import probes


MAX_TARGETS = 256
MAX_EXPOSURE_TASKS = 8192

DEFAULT_SECURITY_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
    1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 9200, 11211, 27017,
]

SERVICE_BY_PORT = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS",
    443: "HTTPS", 445: "SMB", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 2375: "Docker API", 2376: "Docker TLS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP", 8443: "HTTPS",
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

HIGH_RISK_SERVICES = {"Telnet", "FTP", "SMB", "Redis", "MongoDB", "Memcached", "Docker API"}
MEDIUM_RISK_SERVICES = {"RDP", "NetBIOS", "RPC", "MySQL", "PostgreSQL", "MSSQL",
                        "Oracle", "NFS", "Elasticsearch", "VNC", "Docker TLS"}
BANNER_PORTS = {21, 22, 23, 25, 110, 143, 445, 587, 993, 995, 1433, 3306, 5432, 6379}
HTTP_PORTS = {80, 8080, 8000, 8888, 9200}
HTTPS_PORTS = {443, 8443, 9443}


class ExposureRunIn(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=MAX_TARGETS)
    ports: list[int] = []
    discover_hosts: bool = True
    ping_count: int = Field(default=2, ge=1, le=5)
    ping_timeout_ms: int = Field(default=1000, ge=100, le=5000)
    tcp_timeout_s: float = Field(default=2, ge=0.5, le=10)
    service_timeout_s: float = Field(default=2, ge=0.5, le=10)
    verify_tls: bool = False
    concurrency: int = Field(default=64, ge=1, le=256)
    tcp_concurrency: int = Field(default=128, ge=1, le=512)


class ExposureAnalyzeIn(BaseModel):
    summary: dict = {}
    assets: list[dict] = []
    findings: list[dict] = []


def normalize_ports(ports: list[int]) -> list[int]:
    unique = sorted({int(p) for p in ports if 1 <= int(p) <= 65535})
    return unique or list(DEFAULT_SECURITY_PORTS)


def _base_endpoint(host: str, port: int) -> dict:
    return {
        "type": "exposure",
        "target": host,
        "port": port,
        "endpoint": f"{host}:{port}",
        "service": SERVICE_BY_PORT.get(port, "TCP"),
        "status": "open",
        "detail": "端口开放",
        "elapsed_ms": 0.0,
        "banner": "",
        "http": {},
        "tls": {},
        "findings": [],
    }


def _finding(title: str, severity: str, evidence: str, advice: str) -> dict:
    return {
        "title": title,
        "severity": severity,
        "evidence": evidence[:300],
        "advice": advice,
    }


async def _read_banner(host: str, port: int, timeout_s: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout_s
        )
    except Exception:
        return ""
    try:
        chunk = await asyncio.wait_for(reader.read(256), timeout=min(1.0, timeout_s))
        return chunk.decode("utf-8", errors="replace").strip().replace("\n", " / ")
    except Exception:
        return ""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _certificate_info(host: str, port: int, timeout_s: float) -> dict:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=timeout_s,
        )
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if not der:
            return {}
        cert = x509.load_der_x509_certificate(der)
        not_after = cert.not_valid_after_utc
        days_left = round((not_after - datetime.now(timezone.utc)).total_seconds() / 86400)
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        return {
            "subject": subject[:300],
            "issuer": issuer[:300],
            "not_after": not_after.date().isoformat(),
            "days_left": days_left,
            "self_signed": cert.issuer == cert.subject,
        }
    except Exception as exc:
        return {"error": f"TLS 证书读取失败: {exc}"}


async def _http_info(host: str, port: int, verify_tls: bool,
                     timeout_s: float) -> dict:
    scheme = "https" if port in HTTPS_PORTS else "http"
    url = f"{scheme}://{host}:{port}/"
    client = httpx.AsyncClient(
        follow_redirects=False,
        verify=verify_tls,
        timeout=httpx.Timeout(timeout_s),
    )
    try:
        response = await client.head(url)
        headers = {key.lower(): value for key, value in response.headers.items()}
        return {
            "url": url,
            "status": response.status_code,
            "server": headers.get("server", "")[:200],
            "content_type": headers.get("content-type", "")[:200],
            "missing_security_headers": [
                name for name in ("content-security-policy", "x-content-type-options", "x-frame-options")
                if name not in headers
            ],
        }
    except httpx.TimeoutException:
        return {"url": url, "error": "HTTP 探测超时"}
    except httpx.SSLError as exc:
        return {"url": url, "error": f"HTTP/TLS 探测失败: {exc}"}
    except httpx.HTTPError as exc:
        return {"url": url, "error": f"HTTP 探测失败: {exc}"}
    finally:
        await client.aclose()


def _endpoint_findings(endpoint: dict) -> list[dict]:
    findings: list[dict] = []
    service = endpoint["service"]
    port = endpoint["port"]
    evidence = f"{endpoint['endpoint']} {service}"
    if service in HIGH_RISK_SERVICES:
        advice = {
            "Telnet": "关闭 Telnet，改用 SSHv2，并绑定管理源地址 ACL。",
            "FTP": "关闭 FTP，改用 SFTP/SCP，并限制可访问网段。",
            "SMB": "限制 SMB 暴露范围，关闭旧版本协议并确认共享权限。",
            "Redis": "为 Redis 配置 requirepass/ACL 和 bind 地址，禁止直接公网访问。",
            "MongoDB": "启用认证和 TLS，使用 bindIp 限制访问来源。",
            "Memcached": "限制 UDP/TCP 来源，启用 SASL，避免用于反射放大攻击。",
            "Docker API": "禁用无 TLS 的 Docker API，使用 Unix socket 或强证书认证。",
        }.get(service, "关闭不必要的对外暴露，加入访问控制。")
        findings.append(_finding(f"高危服务 {service} 暴露", "high", evidence, advice))
    elif service in MEDIUM_RISK_SERVICES:
        findings.append(_finding(
            f"管理/数据服务 {service} 暴露", "medium", evidence,
            "确认是否必须对外可达，收紧防火墙/安全组并启用认证与加密。",
        ))

    banner = endpoint.get("banner", "")
    if banner and any(token.lower() in banner.lower() for token in ("version", "v1.", "v2.", "v3.", "openssh", "microsoft", "vsftpd")):
        findings.append(_finding(
            "服务版本信息暴露", "low", banner,
            "隐藏软件版本信息，保持补丁更新，并在边界过滤无用 Banner。",
        ))

    http = endpoint.get("http", {})
    if http and not http.get("error") and 200 <= int(http.get("status", 0)) < 300:
        missing = http.get("missing_security_headers", [])
        if missing:
            findings.append(_finding(
                "HTTP 安全响应头缺失", "low", ", ".join(missing),
                "按应用类型补充 CSP、X-Content-Type-Options、X-Frame-Options 等安全头。",
            ))

    tls = endpoint.get("tls", {})
    if tls:
        if tls.get("self_signed"):
            findings.append(_finding(
                "TLS 证书疑似自签名", "medium", tls.get("subject", ""),
                "使用可信 CA 证书或内部根 CA 签发证书，并配置完整信任链。",
            ))
        if isinstance(tls.get("days_left"), int):
            if tls["days_left"] < 0:
                findings.append(_finding("TLS 证书已过期", "high", tls["not_after"], "立即更换证书并建立到期监控。"))
            elif tls["days_left"] <= 14:
                findings.append(_finding("TLS 证书即将过期", "medium", tls["not_after"], "尽快更换证书并建立到期监控。"))
    return findings


async def _fingerprint(host: str, port: int, body: ExposureRunIn,
                       semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        started = time.perf_counter()
        endpoint = _base_endpoint(host, port)
        timeout = body.service_timeout_s
        if port in HTTP_PORTS:
            endpoint["http"] = await _http_info(host, port, False, timeout)
        elif port in HTTPS_PORTS:
            endpoint["http"] = await _http_info(host, port, False, timeout)
            endpoint["tls"] = await _certificate_info(host, port, timeout)
        elif port in BANNER_PORTS:
            endpoint["banner"] = await _read_banner(host, port, timeout)

        endpoint["findings"] = _endpoint_findings(endpoint)
        endpoint["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)
        endpoint["detail"] = endpoint.get("banner") or endpoint.get("http", {}).get(
            "server", endpoint["detail"]
        )
        return endpoint


async def _scan_tcp(host: str, port: int, body: ExposureRunIn,
                    semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        return await probes.probe_tcp(host, port, body.tcp_timeout_s)


def _asset(target: str, status: str, detail: str, ports: list[int] | None = None) -> dict:
    return {
        "type": "asset",
        "target": target,
        "status": status,
        "detail": detail,
        "open_ports": ports or [],
        "findings": [],
    }


async def run_exposure(body: ExposureRunIn) -> AsyncIterator[dict]:
    targets = probes.clean_targets(body.targets)[:MAX_TARGETS]
    if not targets:
        yield {"type": "error", "message": "没有有效目标"}
        return
    ports = normalize_ports(body.ports)
    if len(targets) * len(ports) > MAX_EXPOSURE_TASKS:
        yield {"type": "error", "message": "目标端口组合超过 8192，请减少目标或端口"}
        return

    started = time.perf_counter()
    alive: list[str] = []
    asset_by_target: dict[str, dict] = {}
    findings: list[dict] = []
    endpoints: list[dict] = []

    yield {
        "type": "start",
        "target_total": len(targets),
        "port_count": len(ports),
        "discover_hosts": body.discover_hosts,
    }

    if body.discover_hosts:
        semaphore = asyncio.Semaphore(body.concurrency)

        async def ping_one(target: str) -> dict:
            async with semaphore:
                return await probes._run_ping(target, body.ping_count, body.ping_timeout_ms)

        tasks = [asyncio.create_task(ping_one(target)) for target in targets]
        done = 0
        try:
            for awaitable in asyncio.as_completed(tasks):
                result = await awaitable
                done += 1
                is_alive = result.get("ok") is True
                if is_alive:
                    alive.append(result["target"])
                asset = _asset(
                    result["target"],
                    "alive" if is_alive else str(result.get("status", "timeout")),
                    result.get("detail", ""),
                )
                asset_by_target[result["target"]] = asset
                yield {"type": "result", "result": asset, "done": done, "total": len(targets)}
                yield {"type": "progress", "phase": "discover", "done": done, "total": len(targets)}
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    else:
        alive = list(targets)
        for target in targets:
            asset_by_target[target] = _asset(target, "assumed", "未启用存活探测，直接检查端口")
        yield {"type": "progress", "phase": "discover", "done": len(targets), "total": len(targets)}

    tcp_semaphore = asyncio.Semaphore(body.tcp_concurrency)
    fingerprint_semaphore = asyncio.Semaphore(min(256, body.tcp_concurrency))
    tcp_tasks = [
        asyncio.create_task(_scan_tcp(host, port, body, tcp_semaphore))
        for host in alive for port in ports
    ]
    total_open = 0
    scanned = 0
    try:
        for awaitable in asyncio.as_completed(tcp_tasks):
            result = await awaitable
            scanned += 1
            if result.get("status") != "open":
                continue
            total_open += 1
            endpoint = await _fingerprint(
                result["target"], result["port"], body, fingerprint_semaphore
            )
            endpoint["findings"] = _endpoint_findings(endpoint)
            endpoints.append(endpoint)
            findings.extend(endpoint["findings"])
            asset = asset_by_target.setdefault(result["target"], _asset(result["target"], "alive", "端口可达"))
            asset.setdefault("open_ports", []).append(result["port"])
            asset["open_ports"].sort()
            yield {"type": "result", "result": endpoint, "done": total_open, "total": total_open}
            yield {"type": "progress", "phase": "service", "done": scanned, "total": len(tcp_tasks)}
    finally:
        for task in tcp_tasks:
            task.cancel()
        await asyncio.gather(*tcp_tasks, return_exceptions=True)

    risk_counts: dict[str, int] = {}
    for finding in findings:
        risk_counts[finding["severity"]] = risk_counts.get(finding["severity"], 0) + 1
    yield {
        "type": "summary",
        "targets_total": len(targets),
        "hosts_alive": len(alive),
        "endpoint_total": len(alive) * len(ports),
        "open_count": total_open,
        "finding_count": len(findings),
        "risk_counts": risk_counts,
        "duration_ms": round((time.perf_counter() - started) * 1000, 1),
        "assets": list(asset_by_target.values())[:256],
    }
