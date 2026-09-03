"""Small in-process job manager used by long-running local operations."""

from __future__ import annotations

import asyncio
import secrets
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class JobManager:
    def __init__(self) -> None:
        self.jobs: dict[str, dict[str, Any]] = {}
        self._locks: set[str] = set()

    def create(self, kind: str, target_key: str,
               factory: Callable[[Callable[[dict[str, Any]], None]], Awaitable[Any]]) -> dict[str, Any]:
        if target_key and target_key in self._locks:
            raise ValueError("该目标已有任务正在运行")
        job_id = secrets.token_urlsafe(12)
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        record = {
            "id": job_id, "kind": kind, "target_key": target_key, "status": "queued",
            "created_at": _now(), "started_at": None, "finished_at": None,
            "result": None, "error": "", "queue": queue, "task": None,
        }
        self.jobs[job_id] = record
        if target_key:
            self._locks.add(target_key)

        def emit(event: dict[str, Any]) -> None:
            loop.call_soon_threadsafe(queue.put_nowait, event)

        async def runner() -> None:
            record["status"] = "running"
            record["started_at"] = _now()
            emit({"type": "start", "job_id": job_id, "kind": kind})
            try:
                result = await factory(emit)
                record["result"] = result
                status = result.get("status") if isinstance(result, dict) else None
                record["status"] = status if status in {"succeeded", "partial", "failed"} else "succeeded"
                emit({"type": "result", "job_id": job_id, "result": result})
            except asyncio.CancelledError:
                record["status"] = "cancelled"
                emit({"type": "cancelled", "job_id": job_id})
            except Exception as exc:
                record["status"] = "failed"
                record["error"] = str(exc)
                emit({"type": "error", "job_id": job_id, "message": str(exc)})
            finally:
                record["finished_at"] = _now()
                if target_key:
                    self._locks.discard(target_key)
                emit({"type": "done", "job_id": job_id, "status": record["status"]})

        record["task"] = asyncio.create_task(runner())
        return self.public(job_id)

    def public(self, job_id: str) -> dict[str, Any]:
        record = self.jobs.get(job_id)
        if not record:
            raise ValueError("任务不存在或已过期")
        return {key: value for key, value in record.items() if key not in {"queue", "task"}}

    def cancel(self, job_id: str) -> dict[str, Any]:
        record = self.jobs.get(job_id)
        if not record:
            raise ValueError("任务不存在或已过期")
        task = record.get("task")
        if task and not task.done():
            task.cancel()
        return self.public(job_id)

    async def events(self, job_id: str):
        record = self.jobs.get(job_id)
        if not record:
            raise ValueError("任务不存在或已过期")
        queue: asyncio.Queue = record["queue"]
        yield {"type": "snapshot", "job": self.public(job_id)}
        while True:
            event = await queue.get()
            yield event
            if event.get("type") == "done":
                break


manager = JobManager()

