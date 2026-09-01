import pytest
from fastapi.testclient import TestClient

from app import ai as ai_mod
from app.device_config import audit_config, audit_upload, build_report
from app.main import app


client = TestClient(app)

H3C_CONFIG = """
sysname H3C-Core
telnet server enable
snmp-agent community read public
local-user admin
 password simple Admin123!
interface GigabitEthernet1/0/1
 port link-type trunk
 port trunk permit vlan all
"""

HUAWEI_CONFIG = """
sysname Huawei-Core
vlan batch 10 20
telnet server enable
snmp-agent community read cipher %^%#test
user-interface vty 0 4
"""

ZTE_CONFIG = """
set router-name ZXR10-Router
set ip service telnet enable
snmp-server community private
"""

RUIJIE_CONFIG = """
hostname Ruijie-Switch
enable secret 5 $1$test$test
snmp-server community public ro
line vty 0 4
"""


def test_vendor_detection_and_core_rules():
    result = audit_config(H3C_CONFIG)
    assert result["vendor"] == "H3C"
    ids = {item["id"] for item in result["findings"]}
    assert {"telnet-enabled", "snmp-default-community", "plaintext-password"} <= ids
    assert result["device_name"] == "H3C-Core"


def test_huawei_and_ruijie_detection():
    assert audit_config(HUAWEI_CONFIG)["vendor"] == "Huawei"
    assert audit_config(RUIJIE_CONFIG)["vendor"] == "Ruijie"


def test_zte_detection():
    result = audit_config(ZTE_CONFIG)
    assert result["vendor"] == "ZTE"
    assert any(item["id"] == "telnet-enabled" for item in result["findings"])


def test_sensitive_values_are_redacted():
    result = audit_config(H3C_CONFIG)
    evidence = "\n".join(item["evidence"] for item in result["findings"])
    assert "Admin123!" not in evidence
    assert "public" not in evidence
    assert "***" in evidence


def test_report_and_baseline_checks():
    result = audit_config("sysname Test\n")
    report = build_report("sample.txt", result)
    assert "未发现集中日志服务器" in report
    assert "未发现 NTP 时间同步" in report


def test_upload_api_and_reject_binary():
    resp = client.post("/api/security/config-audit/upload", files={
        "file": ("h3c.cfg", H3C_CONFIG.encode("utf-8"), "text/plain"),
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["vendor"] == "H3C"
    assert "## 详细发现" in data["report"]

    binary = b"config\x00binary"
    resp = client.post("/api/security/config-audit/upload", files={
        "file": ("bad.txt", binary, "text/plain"),
    })
    assert resp.status_code == 400


def test_config_audit_ai_mock(monkeypatch):
    async def fake_stream(messages):
        assert "脱敏" in messages[0]["content"] or "审计" in messages[0]["content"]
        yield "## 结论\n测试通过"

    monkeypatch.setattr(ai_mod, "stream_chat", fake_stream)
    result = audit_upload("h3c.txt", H3C_CONFIG.encode("utf-8"))
    resp = client.post("/api/ai/analyze-config-audit", json={"result": result})
    assert resp.status_code == 200
    assert "测试通过" in resp.text
