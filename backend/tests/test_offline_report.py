import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@pytest.fixture()
def session_id(fixture_pcap):
    with open(fixture_pcap, "rb") as f:
        resp = client.post("/api/upload", files={
            "file": ("fixture.pcap", f, "application/octet-stream"),
        })
    assert resp.status_code == 200
    return resp.json()["session_id"]


def test_offline_report_overview(session_id):
    resp = client.post("/api/offline-report", json={
        "session_id": session_id, "scope": "overview",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["generated_by"] == "local-rules"
    markdown = data["markdown"]
    assert "# Packet Lens 离线诊断报告" in markdown
    assert "本地规则引擎生成" in markdown
    assert "TCP RST / RST+ACK" in markdown
    assert "TCP 重传" in markdown
    assert "DNS 解析失败" in markdown
    assert "TLS Alert" in markdown
    assert "重点报文证据" in markdown
    assert "排查建议" in markdown


def test_offline_report_selected_packets(session_id):
    rows = client.get("/api/packets", params={
        "session_id": session_id, "rule": "rst",
    }).json()["packets"]
    assert rows
    resp = client.post("/api/offline-report", json={
        "session_id": session_id,
        "scope": "packets",
        "packet_nos": [row["no"] for row in rows],
    })
    assert resp.status_code == 200
    markdown = resp.json()["markdown"]
    assert "选中报文（1 条）" in markdown
    assert "规则解读：TCP RST / RST+ACK" in markdown


def test_offline_report_flow_scope(session_id):
    packet = client.get(f"/api/packets/{session_id}/1").json()
    resp = client.post("/api/offline-report", json={
        "session_id": session_id,
        "scope": "flow",
        "flow_key": packet["flow"],
    })
    assert resp.status_code == 200
    markdown = resp.json()["markdown"]
    assert "单条流" in markdown
    assert packet["flow"] in markdown
    assert "关键流" in markdown


def test_offline_report_requires_selection(session_id):
    resp = client.post("/api/offline-report", json={
        "session_id": session_id,
        "scope": "packets",
        "packet_nos": [],
    })
    assert resp.status_code == 400


def test_offline_report_session_not_found():
    resp = client.post("/api/offline-report", json={
        "session_id": "missing", "scope": "overview",
    })
    assert resp.status_code == 404


def test_offline_probe_report_ping():
    resp = client.post("/api/offline-probe-report", json={
        "probe_type": "ping",
        "summary": {
            "statuses": {"reachable": 1, "timeout": 1},
            "ok_count": 1, "error_count": 1, "duration_ms": 100,
        },
        "results": [
            {"type": "ping", "target": "127.0.0.1", "ok": True,
             "status": "reachable", "avg_ms": 1.2, "sent": 2,
             "replies": 2, "loss": 0, "detail": "2/2 应答"},
            {"type": "ping", "target": "10.255.255.1", "ok": False,
             "status": "timeout", "avg_ms": None, "sent": 2,
             "replies": 0, "loss": 2, "detail": "Ping 超时"},
        ],
    })
    assert resp.status_code == 200
    markdown = resp.json()["markdown"]
    assert "网络探测离线报告" in markdown
    assert "10.255.255.1" in markdown
    assert "路由跟踪" in markdown


def test_offline_probe_report_tcp_and_http():
    resp = client.post("/api/offline-probe-report", json={
        "probe_type": "tcp",
        "summary": {"statuses": {"open": 1, "closed": 1}, "ok_count": 1,
                    "error_count": 1, "duration_ms": 50},
        "results": [
            {"type": "tcp", "target": "127.0.0.1", "port": 80,
             "endpoint": "127.0.0.1:80", "ok": True, "status": "open",
             "detail": "端口开放", "elapsed_ms": 1},
            {"type": "tcp", "target": "127.0.0.1", "port": 9999,
             "endpoint": "127.0.0.1:9999", "ok": False, "status": "closed",
             "detail": "连接被拒绝", "elapsed_ms": 1},
        ],
    })
    assert resp.status_code == 200
    assert "资产基线" in resp.json()["markdown"]

    resp = client.post("/api/offline-probe-report", json={
        "probe_type": "http",
        "summary": {"statuses": {"server_error": 1}, "ok_count": 0,
                    "error_count": 1, "duration_ms": 30},
        "results": [{"type": "http", "target": "http://127.0.0.1/",
                     "ok": False, "status": "500", "category": "server_error",
                     "detail": "HTTP 500", "elapsed_ms": 5}],
    })
    assert resp.status_code == 200
    assert "HTTP 5xx" in resp.json()["markdown"]
