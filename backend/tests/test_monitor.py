import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app import monitor as monitor_mod
from app.monitor import MonitorService, MonitorStore, MonitorTaskIn


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setattr(monitor_mod, "db_path", lambda: tmp_path / "monitor.db")
    store = MonitorStore()
    try:
        yield MonitorService(store)
    finally:
        store.close()


def _task(name="核心巡检", probe_type="ping"):
    return MonitorTaskIn(
        name=name,
        probe_type=probe_type,
        targets=["127.0.0.1"],
        interval_seconds=60,
        ping_count=2,
        ping_timeout_ms=100,
    )


def _fake_probe(results):
    async def run_probe(_body):
        for result in results:
            yield {"type": "result", "result": result}
        yield {
            "type": "summary",
            "total": len(results),
            "ok_count": sum(bool(item.get("ok")) for item in results),
            "error_count": sum(not bool(item.get("ok")) for item in results),
            "duration_ms": 25,
            "statuses": {},
        }
    return run_probe


def test_create_and_claim_task_uses_utc(service):
    task = service.create_task(_task())
    next_run = datetime.fromisoformat(task["next_run_at"])
    assert next_run.tzinfo is not None

    old_next_run = task["next_run_at"]
    assert service.claim_due(task["id"], old_next_run) is True

    claimed = service.get_task(task["id"])
    expected = datetime.now(timezone.utc) + timedelta(seconds=60)
    assert abs(datetime.fromisoformat(claimed["next_run_at"]) - expected) < timedelta(seconds=10)
    assert service.claim_due(task["id"], old_next_run) is False


def test_run_history_and_latest_diff(service, monkeypatch):
    task = service.create_task(_task())

    monkeypatch.setattr(
        monitor_mod.probes,
        "run_probe",
        _fake_probe([{"target": "127.0.0.1", "status": "reachable", "ok": True, "avg_ms": 10}]),
    )
    first = asyncio.run(service.run_task(task["id"], "manual"))
    assert first["ok_count"] == 1

    diff = service.diff_latest(task["id"])
    assert diff["has_previous"] is False

    monkeypatch.setattr(
        monitor_mod.probes,
        "run_probe",
        _fake_probe([{"target": "127.0.0.1", "status": "reachable", "ok": True, "avg_ms": 120}]),
    )
    second = asyncio.run(service.run_task(task["id"], "scheduled"))
    assert second["trigger"] == "scheduled"

    updated = service.get_task(task["id"])
    assert updated["last_status"] == "正常"
    assert datetime.fromisoformat(updated["next_run_at"]).tzinfo is not None

    latest = service.diff_latest(task["id"])
    assert latest["has_previous"] is True
    assert [change["kind"] for change in latest["changes"]] == ["latency"]


def test_error_run_is_persisted(service, monkeypatch):
    task = service.create_task(_task())

    async def failing_probe(_body):
        raise RuntimeError("探测失败")
        yield

    monkeypatch.setattr(monitor_mod.probes, "run_probe", failing_probe)
    run = asyncio.run(service.run_task(task["id"]))
    assert run["status"] == "error"
    assert service.get_task(task["id"])["last_status"] == "异常"
