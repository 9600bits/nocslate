import asyncio
import http.server
import socket
import threading

import pytest
from fastapi.testclient import TestClient

from app import ai as ai_mod
from app import config as config_mod
from app import main as main_mod
from app import probes
from app.main import app


client = TestClient(app)


def test_static_fallback_blocks_path_traversal():
    resp = client.get("/../../backend/config.json")
    assert resp.status_code == 200
    assert "deepseek" not in resp.text


def test_upload_size_limit_is_streamed(fixture_pcap, monkeypatch):
    monkeypatch.setattr(main_mod, "MAX_UPLOAD_BYTES", 8)
    with open(fixture_pcap, "rb") as f:
        resp = client.post("/api/upload", files={
            "file": ("large.pcap", f, "application/octet-stream"),
        })
    assert resp.status_code == 413
    assert resp.json()["detail"] == "文件过大（上限 200MB）"


def test_config_save_failure_returns_500(monkeypatch):
    def fail_save(_update):
        raise RuntimeError("配置文件写入失败：disk-full")

    monkeypatch.setattr(config_mod, "save", fail_save)
    resp = client.put("/api/config", json={"model": "should-not-save"})
    assert resp.status_code == 500
    assert "配置文件写入失败" in resp.json()["detail"]


def test_model_scan_endpoint():
    async def fake_models(base_url, api_key):
        assert base_url == "https://ai.example.com/v1"
        assert api_key == "sk-test"
        return ["model-a", "model-b"]

    original = ai_mod.list_models
    ai_mod.list_models = fake_models
    try:
        resp = client.post("/api/ai/models", json={
            "base_url": "https://ai.example.com/v1",
            "api_key": "sk-test",
        })
    finally:
        ai_mod.list_models = original
    assert resp.status_code == 200
    assert resp.json() == {"models": ["model-a", "model-b"]}


def test_model_scan_uses_saved_key(monkeypatch):
    saved = {}
    async def fake_models(base_url, api_key):
        saved["api_key"] = api_key
        return ["m"]

    monkeypatch.setattr(ai_mod, "list_models", fake_models)
    client.put("/api/config", json={"api_key": "sk-existing-123"})
    resp = client.post("/api/ai/models", json={
        "base_url": "https://ai.example.com/v1",
        "api_key": "__KEEP__",
    })
    assert resp.status_code == 200
    assert saved["api_key"] == "sk-existing-123"
    client.put("/api/config", json={"api_key": ""})


def _run(coro):
    return asyncio.run(coro)


@pytest.mark.parametrize("payload,expected", [
    ({"data": [{"id": "b"}, {"id": "a"}, {"id": "b"}]}, ["b", "a"]),
    ({"models": [{"id": "glm"}, {"id": "deepseek"}]}, ["glm", "deepseek"]),
    (["one", "two", "one"], ["one", "two"]),
])
def test_list_models_parses_three_shapes(monkeypatch, payload, expected):
    class FakeResponse:
        status_code = 200
        text = ""
        def json(self):
            return payload

    class FakeClient:
        def __init__(self, **_kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *_args):
            return False
        async def get(self, *_args, **_kwargs):
            return FakeResponse()

    monkeypatch.setattr(ai_mod.httpx, "AsyncClient", FakeClient)
    assert _run(ai_mod.list_models("https://ai.example.com/v1", "key")) == expected


def test_parse_ping_output_chinese_and_english():
    gbk_output = "来自 127.0.0.1 的回复: 字节=32 时间=5ms TTL=128".encode("gbk")
    decoded = probes.parse_ping_output(probes._decode_process_output(gbk_output), 1)
    assert decoded["replies"] == 1 and decoded["avg_ms"] == 5

    chinese = "\n".join([
        "来自 127.0.0.1 的回复: 字节=32 时间<1ms TTL=128",
        "来自 127.0.0.1 的回复: 字节=32 时间=3ms TTL=128",
        "最短 = 0ms，最长 = 3ms，平均 = 2ms",
    ])
    assert probes.parse_ping_output(chinese, 4) == {
        "replies": 2, "loss": 2, "avg_ms": 2, "status": "reachable",
    }
    english = "\n".join([
        "Reply from 10.0.0.1: bytes=32 time=12ms TTL=64",
        "Reply from 10.0.0.1: bytes=32 time=14ms TTL=64",
        "Minimum = 12ms, Maximum = 14ms, Average = 13ms",
    ])
    assert probes.parse_ping_output(english, 2) == {
        "replies": 2, "loss": 0, "avg_ms": 13, "status": "reachable",
    }
    timeout = probes.parse_ping_output("Request timed out.", 2)
    assert timeout["status"] == "timeout" and timeout["replies"] == 0


def test_ping_helpers_and_large_count_validation():
    assert probes._ping_latency("Reply: time<1ms TTL=64") == 0.0
    assert probes._ping_latency("Reply: time=12ms TTL=64") == 12.0
    assert probes._is_ping_reply("来自 127.0.0.1: 字节=32 时间=1ms TTL=128")
    assert probes._is_ping_timeout("Request timed out.")
    assert probes._is_ping_timeout("请求超时。")
    assert probes.ProbeRunIn(type="ping", targets=["127.0.0.1"], ping_count=65536).ping_count == 65536


def test_run_ping_emits_streaming_updates(monkeypatch):
    class FakeStream:
        def __init__(self, lines):
            self.lines = list(lines)

        async def readline(self):
            if not self.lines:
                return b""
            return self.lines.pop(0)

    class FakeProcess:
        def __init__(self, lines):
            self.stdout = FakeStream(lines)
            self.returncode = 0

        async def wait(self):
            return 0

    def fake_exec(*_args, **_kwargs):
        lines = [
            "Reply from 127.0.0.1: time=3ms TTL=128".encode(),
            "Reply from 127.0.0.1: time<1ms TTL=128".encode(),
            "Request timed out.".encode(),
        ]

        async def create(*_args, **_kwargs):
            return FakeProcess(lines)

        return create()

    monkeypatch.setattr(probes.asyncio, "create_subprocess_exec", fake_exec)

    async def collect():
        updates = []

        def on_update(event):
            updates.append(event)

        result = await probes._run_ping("127.0.0.1", 3, 100, on_update)
        return updates, result

    updates, result = _run(collect())
    assert [event["sequence"] for event in updates] == [1, 2, 3]
    assert [event["latency_ms"] for event in updates] == [3.0, 0.0, None]
    assert updates[1]["replies"] == 2 and updates[1]["avg_ms"] == 1.5
    assert updates[-1]["loss"] == 1
    assert result["status"] == "reachable" and result["replies"] == 2
    assert result["sent"] == 3 and result["loss"] == 1


def test_normalize_ports_and_targets():
    assert probes.clean_targets(["a.com", "a.com", "", "b.com"]) == ["a.com", "b.com"]
    assert probes.normalize_ports([])[0] == 21
    assert probes.normalize_ports([8080, 80, 8080, 0, 70000]) == [80, 8080]


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args):
        pass


def _start_http_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_probe_tcp_open_and_http_status():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        tcp = _run(probes.probe_tcp("127.0.0.1", port, 1))
        assert tcp["status"] == "open" and tcp["ok"] is True
    finally:
        listener.close()

    server = _start_http_server()
    try:
        http_result = _run(probes.probe_http(
            f"127.0.0.1:{server.server_address[1]}", "GET", False, True, 2,
        ))
        assert http_result["status"] == "204"
        assert http_result["ok"] is True
    finally:
        server.shutdown()
        server.server_close()


def test_run_probe_streams_result_and_summary():
    body = probes.ProbeRunIn(type="tcp", targets=["127.0.0.1"], ports=[9], tcp_concurrency=2)
    async def collect():
        events = []
        async for event in probes.run_probe(body):
            events.append(event)
        return events
    events = _run(collect())
    assert events[0]["type"] == "start" and events[0]["total"] == 1
    assert events[1]["type"] == "result"
    assert events[-1]["type"] == "summary"
    assert events[-1]["statuses"]["closed"] == 1


def test_run_probe_http_summary_uses_category():
    class FakeResponse:
        status_code = 200
        reason_phrase = "OK"
        url = "http://127.0.0.1/test"
        headers = {}

    class FakeClient:
        created = 0

        def __init__(self, **_kwargs):
            FakeClient.created += 1

        async def request(self, *_args, **_kwargs):
            return FakeResponse()

        async def aclose(self):
            pass

    body = probes.ProbeRunIn(type="http", targets=["127.0.0.1"])

    async def collect():
        events = []
        async for event in probes.run_probe(body):
            events.append(event)
        return events

    original_client = probes.httpx.AsyncClient
    probes.httpx.AsyncClient = FakeClient
    try:
        events = _run(collect())
    finally:
        probes.httpx.AsyncClient = original_client

    assert FakeClient.created == 1
    assert events[1]["result"]["category"] == "ok"
    assert events[-1]["statuses"] == {"ok": 1}
    assert events[-1]["ok_count"] == 1
    assert events[-1]["error_count"] == 0


def test_probe_context_prioritizes_bad_results():
    results = [
        {"target": "good", "ok": True, "status": "ok"},
        {"target": "bad", "ok": False, "status": "timeout"},
    ]
    context = ai_mod.build_probe_context("http", {"total": 2}, results)
    assert "timeout" in context and "good" in context
