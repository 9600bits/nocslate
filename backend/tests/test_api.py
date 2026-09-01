import pytest
from fastapi.testclient import TestClient

from app import ai as ai_mod
from app.main import app

client = TestClient(app)


def upload(fixture_pcap):
    with open(fixture_pcap, "rb") as f:
        resp = client.post("/api/upload", files={
            "file": ("fixture.pcap", f, "application/octet-stream"),
        })
    assert resp.status_code == 200
    return resp.json()


def test_upload_and_rule_summary(fixture_pcap):
    data = upload(fixture_pcap)
    assert data["packet_count"] == 32
    assert data["capped"] is False
    rs = data["rule_summary"]
    assert rs["rst"] == 1
    assert rs["retransmission"] == 2
    assert rs["zero_window"] == 1
    assert rs["syn_halfopen"] == 2
    assert rs["syn_scan"] == 15
    assert rs["dns_fail"] == 1
    assert rs["http_error"] == 1
    assert rs["tls_alert"] == 1
    assert rs["icmp_err"] == 1


def test_packet_filters(fixture_pcap):
    sid = upload(fixture_pcap)["session_id"]
    resp = client.get("/api/packets", params={"session_id": sid, "rule": "rst"})
    rows = resp.json()["packets"]
    assert resp.json()["total"] == 1
    assert rows[0]["tcp_flags"] == "RA"
    assert rows[0]["hits"][0]["rule"] == "rst"

    resp = client.get("/api/packets", params={"session_id": sid, "proto": "ICMP"})
    assert resp.json()["total"] == 1

    resp = client.get("/api/packets", params={"session_id": sid, "q": "404"})
    assert resp.json()["total"] == 1

    resp = client.get("/api/packets", params={"session_id": sid, "hits_only": "true"})
    assert resp.json()["total"] == 24


def test_packet_detail_payload_preview(fixture_pcap):
    sid = upload(fixture_pcap)["session_id"]
    rows = client.get("/api/packets", params={
        "session_id": sid, "rule": "http_error",
    }).json()["packets"]
    no = rows[0]["no"]
    detail = client.get(f"/api/packets/{sid}/{no}").json()
    assert detail["http"]["code"] == 404
    assert detail["payload_preview"].startswith("485454502f")  # "HTTP/"


def test_rules_endpoint():
    resp = client.get("/api/rules").json()
    assert len(resp["rules"]) == 9
    ids = {r["id"] for r in resp["rules"]}
    assert {"rst", "retransmission", "syn_halfopen", "dns_fail"} <= ids


def test_config_roundtrip():
    try:
        resp = client.put("/api/config", json={
            "base_url": "https://api.example.com/v1",
            "model": "test-model",
            "api_key": "sk-test-1234567890",
        }).json()
        assert resp["has_key"] is True
        assert "sk-test-1234567890" not in resp["api_key_masked"]
        assert client.get("/api/config").json()["model"] == "test-model"
        kept = client.put("/api/config", json={"model": "m2", "api_key": "__KEEP__"}).json()
        assert kept["has_key"] is True
    finally:
        client.put("/api/config", json={
            "base_url": "https://api.deepseek.com/v1",
            "model": "deepseek-chat",
            "api_key": "",
        })


def test_ai_without_key_returns_error_event(fixture_pcap):
    client.put("/api/config", json={"api_key": ""})
    sid = upload(fixture_pcap)["session_id"]
    resp = client.post("/api/ai/analyze", json={"session_id": sid, "scope": "overview"})
    assert resp.status_code == 200
    assert '"error"' in resp.text


def test_ai_mock_stream(fixture_pcap, monkeypatch):
    async def fake_stream(messages):
        assert messages[0]["role"] == "system"
        yield "现象："
        yield " 测试通过"

    monkeypatch.setattr(ai_mod, "stream_chat", fake_stream)
    sid = upload(fixture_pcap)["session_id"]
    resp = client.post("/api/ai/analyze", json={
        "session_id": sid, "scope": "packets", "packet_nos": [1, 2],
    })
    assert "现象：" in resp.text and "测试通过" in resp.text
    assert "[DONE]" in resp.text


def test_ai_flow_scope_with_mock(fixture_pcap, monkeypatch):
    async def fake_stream(messages):
        yield "流分析 OK"

    monkeypatch.setattr(ai_mod, "stream_chat", fake_stream)
    sid = upload(fixture_pcap)["session_id"]
    first = client.get(f"/api/packets/{sid}/1").json()
    resp = client.post("/api/ai/analyze", json={
        "session_id": sid, "scope": "flow", "flow_key": first["flow"],
    })
    assert "流分析 OK" in resp.text
