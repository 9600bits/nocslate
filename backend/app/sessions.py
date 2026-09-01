from __future__ import annotations

import threading
import time
import uuid

_sessions: dict[str, dict] = {}
_lock = threading.Lock()
MAX_SESSIONS = 5


def create(filename: str, packets: list[dict], rule_result: dict,
           capped: bool, protocols: dict) -> tuple[str, dict]:
    session_id = uuid.uuid4().hex[:12]
    times = [p["ts"] for p in packets]
    entry = {
        "id": session_id,
        "filename": filename,
        "created": time.time(),
        "packets": packets,
        "hits": rule_result["packet_hits"],
        "flow_stats": rule_result["flow_stats"],
        "rule_summary": rule_result["rule_summary"],
        "protocols": protocols,
        "capped": capped,
        "packet_count": len(packets),
        "time_start": min(times) if times else None,
        "time_end": max(times) if times else None,
    }
    with _lock:
        _sessions[session_id] = entry
        while len(_sessions) > MAX_SESSIONS:
            oldest = min(_sessions.values(), key=lambda s: s["created"])
            del _sessions[oldest["id"]]
    return session_id, entry


def get(session_id: str) -> dict | None:
    return _sessions.get(session_id)


def summary(entry: dict) -> dict:
    return {
        "session_id": entry["id"],
        "filename": entry["filename"],
        "packet_count": entry["packet_count"],
        "capped": entry["capped"],
        "protocols": entry["protocols"],
        "rule_summary": entry["rule_summary"],
        "flow_stats": entry["flow_stats"],
        "time_start": entry["time_start"],
        "time_end": entry["time_end"],
    }
