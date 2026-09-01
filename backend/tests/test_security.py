import asyncio

import pytest

from app import report as report_mod
from app import security
from app.security import ExposureRunIn, run_exposure


def test_normalize_ports_defaults_and_limits():
    assert security.normalize_ports([])[0] == 21
    assert security.normalize_ports([0, 80, 80, 70000]) == [80]


def test_endpoint_risk_findings():
    endpoint = security._base_endpoint("192.168.1.10", 23)
    endpoint["banner"] = "OpenSSH"
    findings = security._endpoint_findings(endpoint)
    assert any(item["title"] == "高危服务 Telnet 暴露" for item in findings)

    http_endpoint = security._base_endpoint("192.168.1.10", 80)
    http_endpoint["http"] = {
        "status": 200,
        "missing_security_headers": ["content-security-policy"],
    }
    findings = security._endpoint_findings(http_endpoint)
    assert any(item["title"] == "HTTP 安全响应头缺失" for item in findings)


def test_exposure_report_builder():
    summary = {
        "targets_total": 1, "hosts_alive": 1, "endpoint_total": 2,
        "open_count": 1, "risk_counts": {"high": 1}, "duration_ms": 10,
    }
    markdown = report_mod.build_exposure_report(
        summary,
        [{"target": "192.168.1.10", "status": "alive", "open_ports": [22], "detail": "ok"}],
        [{"title": "SSH 暴露", "severity": "medium", "evidence": "22", "advice": "限制来源"}],
    )
    assert "暴露面与资产发现离线报告" in markdown
    assert "SSH 暴露" in markdown


def test_run_exposure_flow(monkeypatch):
    async def fake_ping(target, count, timeout_ms, on_update=None):
        return {
            "type": "ping", "target": target, "ok": True, "status": "reachable",
            "detail": "1/1 应答", "replies": 1, "sent": count, "loss": 0, "avg_ms": 1,
        }

    async def fake_tcp(host, port, timeout_s=2):
        if port in (22, 23):
            return {"type": "tcp", "target": host, "port": port,
                    "endpoint": f"{host}:{port}", "ok": True, "status": "open"}
        return {"type": "tcp", "target": host, "port": port,
                "endpoint": f"{host}:{port}", "ok": False, "status": "closed"}

    async def fake_fingerprint(host, port, body, semaphore):
        endpoint = security._base_endpoint(host, port)
        endpoint["service"] = "Telnet" if port == 23 else "SSH"
        endpoint["findings"] = security._endpoint_findings(endpoint)
        return endpoint

    monkeypatch.setattr(security.probes, "_run_ping", fake_ping)
    monkeypatch.setattr(security.probes, "probe_tcp", fake_tcp)
    monkeypatch.setattr(security, "_fingerprint", fake_fingerprint)

    async def collect():
        return [event async for event in run_exposure(ExposureRunIn(
            targets=["192.168.1.10"], ports=[22, 23, 80],
            discover_hosts=True, ping_count=1,
        ))]

    events = asyncio.run(collect())
    types = [event["type"] for event in events]
    assert "start" in types and "summary" in types and "[summary]" not in types
    summary = events[-1]
    assert summary["hosts_alive"] == 1
    assert summary["open_count"] == 2
    assert summary["finding_count"] == 1
    assets = [event for event in events if event["type"] == "result" and event["result"]["type"] == "asset"]
    assert assets and assets[0]["result"]["open_ports"] == [22, 23]
