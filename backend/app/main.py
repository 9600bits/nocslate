from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import uuid
from collections import Counter
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import ai, cabinets, config, device_config, parser, probes, report as report_mod, rules as rules_mod, security, sessions
from . import monitor as monitor_mod
from .infra_api import router as infra_router
from .local_auth import middleware as local_auth_middleware
from . import server_ops

MAX_UPLOAD_BYTES = 200 * 1024 * 1024
MAX_CONFIG_AUDIT_BYTES = 20 * 1024 * 1024

app = FastAPI(title="Packet Lens", version="0.7.0")
app.middleware("http")(local_auth_middleware)
app.include_router(infra_router)
monitor_scheduler: asyncio.Task | None = None
inspection_scheduler: asyncio.Task | None = None


@app.on_event("startup")
async def start_monitor() -> None:
    global monitor_scheduler, inspection_scheduler
    monitor_scheduler = asyncio.create_task(monitor_mod.scheduler_loop(monitor_mod.service))
    inspection_scheduler = asyncio.create_task(server_ops.scheduler_loop())


@app.on_event("shutdown")
async def stop_monitor() -> None:
    if monitor_scheduler is not None:
        monitor_scheduler.cancel()
        await asyncio.gather(monitor_scheduler, *monitor_mod.running_tasks, return_exceptions=True)
    if inspection_scheduler is not None:
        inspection_scheduler.cancel()
        await asyncio.gather(inspection_scheduler, return_exceptions=True)


class AnalyzeIn(BaseModel):
    session_id: str
    scope: Literal["overview", "packets", "flow"]
    packet_nos: Optional[list[int]] = None
    flow_key: Optional[str] = None


class ReportIn(AnalyzeIn):
    pass


class ConfigIn(BaseModel):
    base_url: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None


class ModelScanIn(BaseModel):
    base_url: str
    api_key: str = ""


class ConfigAuditAnalyzeIn(BaseModel):
    result: dict = {}


# ---------- cabinets ----------

@app.get("/api/cabinets/rooms")
def cab_rooms():
    return cabinets.store.list_rooms()


@app.post("/api/cabinets/rooms")
def cab_create_room(body: cabinets.RoomIn):
    try:
        return cabinets.store.create_room(body)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.delete("/api/cabinets/rooms/{room_id}")
def cab_delete_room(room_id: int):
    try:
        cabinets.store.delete_room(room_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"ok": True}


@app.get("/api/cabinets/rooms/{room_id}/cabinets")
def cab_list(room_id: int):
    return cabinets.store.list_cabinets(room_id)


@app.post("/api/cabinets/rooms/{room_id}/cabinets")
def cab_create(room_id: int, body: cabinets.CabinetIn):
    try:
        return cabinets.store.create_cabinet(room_id, body)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.put("/api/cabinets/cabinets/{cabinet_id}")
def cab_update(cabinet_id: int, body: cabinets.CabinetIn):
    try:
        return cabinets.store.update_cabinet(cabinet_id, body)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.delete("/api/cabinets/cabinets/{cabinet_id}")
def cab_delete(cabinet_id: int):
    try:
        cabinets.store.delete_cabinet(cabinet_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {"ok": True}


@app.post("/api/cabinets/cabinets/{cabinet_id}/duplicate")
def cab_duplicate(cabinet_id: int, body: cabinets.DuplicateIn):
    try:
        return cabinets.store.duplicate_cabinet(cabinet_id, body.new_name, body.target_room_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/cabinets/cabinets/{cabinet_id}/layout")
def cab_layout(cabinet_id: int):
    try:
        return cabinets.store.cabinet_layout(cabinet_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.get("/api/cabinets/devices")
def cab_devices(cabinet_id: Optional[int] = None, unracked_only: bool = False):
    return cabinets.store.list_devices(cabinet_id, unracked_only)


@app.post("/api/cabinets/devices")
def cab_create_device(body: cabinets.DeviceIn, cabinet_id: Optional[int] = None):
    try:
        return cabinets.store.create_device(cabinet_id, body)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.put("/api/cabinets/devices/{device_id}")
def cab_update_device(device_id: int, body: cabinets.DeviceIn, cabinet_id: Optional[int] = None):
    try:
        return cabinets.store.update_device(device_id, body, cabinet_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.delete("/api/cabinets/devices/{device_id}")
def cab_delete_device(device_id: int):
    cabinets.store.delete_device(device_id)
    return {"ok": True}


@app.post("/api/cabinets/devices/{device_id}/placement")
def cab_place_device(device_id: int, body: cabinets.DevicePlacementIn):
    try:
        return cabinets.store.place_device(device_id, body.cabinet_id, body.u_start)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/cabinets/placement-check")
def cab_placement_check(cabinet_id: int, body: cabinets.PlacementCheckIn):
    return cabinets.store.check_placement(
        cabinet_id, body.u_start, body.u_size, body.exclude_kind, body.exclude_id
    )


@app.get("/api/cabinets/capacity")
def cab_capacity():
    return cabinets.store.capacity()


@app.get("/api/cabinets/templates")
def cab_templates():
    return {"templates": cabinets.store.list_templates()}


@app.post("/api/cabinets/cabinets/{cabinet_id}/template")
def cab_save_template(cabinet_id: int, body: cabinets.TemplateIn):
    try:
        return cabinets.store.save_template(cabinet_id, body)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/cabinets/templates/{template_id}/apply")
def cab_apply_template(template_id: int, body: cabinets.TemplateApplyIn):
    try:
        return {"cabinets": cabinets.store.apply_template(template_id, body)}
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.delete("/api/cabinets/templates/{template_id}")
def cab_delete_template(template_id: int):
    cabinets.store.delete_template(template_id)
    return {"ok": True}


@app.get("/api/cabinets/compare/{left_id}/{right_id}")
def cab_compare(left_id: int, right_id: int):
    try:
        return cabinets.store.compare_cabinets(left_id, right_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


# ---------- monitor ----------

@app.get("/api/monitor/tasks")
def monitor_tasks():
    return {"tasks": monitor_mod.service.list_tasks()}


@app.post("/api/monitor/tasks")
def monitor_create_task(body: monitor_mod.MonitorTaskIn):
    try:
        return monitor_mod.service.create_task(body)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.patch("/api/monitor/tasks/{task_id}")
def monitor_update_task(task_id: int, body: monitor_mod.MonitorUpdateIn):
    try:
        return monitor_mod.service.update_task(task_id, body)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.delete("/api/monitor/tasks/{task_id}")
def monitor_delete_task(task_id: int):
    monitor_mod.service.delete_task(task_id)
    return {"ok": True}


@app.post("/api/monitor/tasks/{task_id}/run")
async def monitor_run_task(task_id: int):
    try:
        return await monitor_mod.service.run_task(task_id, "manual")
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.get("/api/monitor/tasks/{task_id}/runs")
def monitor_runs(task_id: int, limit: int = 50):
    return {"runs": monitor_mod.service.list_runs(task_id, limit)}


@app.get("/api/monitor/runs/{run_id}")
def monitor_run(run_id: int):
    run = monitor_mod.service.get_run(run_id)
    if run is None:
        raise HTTPException(404, "运行记录不存在")
    return run


@app.get("/api/monitor/tasks/{task_id}/diff")
def monitor_diff(task_id: int):
    try:
        return monitor_mod.service.diff_latest(task_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.get("/api/cabinets/reservations")
def cab_reservations(cabinet_id: Optional[int] = None):
    return cabinets.store.list_reservations(cabinet_id)


@app.post("/api/cabinets/reservations")
def cab_create_reservation(cabinet_id: int, body: cabinets.ReservationIn):
    try:
        return cabinets.store.create_reservation(cabinet_id, body)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.delete("/api/cabinets/reservations/{reservation_id}")
def cab_delete_reservation(reservation_id: int):
    cabinets.store.delete_reservation(reservation_id)
    return {"ok": True}


def _upload_dir() -> Path:
    d = Path(tempfile.gettempdir()) / "packet_lens_uploads"
    d.mkdir(parents=True, exist_ok=True)
    return d


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    suffix = Path(file.filename or "capture.pcap").suffix or ".pcap"
    path = _upload_dir() / f"{uuid.uuid4().hex}{suffix}"
    try:
        size = 0
        with path.open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "文件过大（上限 200MB）")
                out.write(chunk)
        packets, capped = await asyncio.to_thread(parser.parse_pcap, str(path))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, f"无法解析该文件: {exc}") from exc
    finally:
        path.unlink(missing_ok=True)
    if not packets:
        raise HTTPException(400, "文件中没有可识别的数据包")

    rule_result = rules_mod.run_rules(packets)
    protocols = dict(Counter(p["proto"] for p in packets))
    session_id, entry = sessions.create(
        file.filename or "capture.pcap", packets, rule_result, capped, protocols
    )
    return sessions.summary(entry)


@app.get("/api/rules")
def list_rules():
    return {"rules": rules_mod.RULES}


@app.get("/api/session/{session_id}")
def get_session(session_id: str):
    entry = sessions.get(session_id)
    if entry is None:
        raise HTTPException(404, "会话不存在或已过期，请重新上传")
    return sessions.summary(entry)


def _filtered_rows(entry: dict, proto: str, rule: str, q: str, hits_only: bool):
    q = q.lower()
    for p in entry["packets"]:
        hits = entry["hits"].get(p["no"], [])
        if proto and p["proto"] != proto:
            continue
        if rule and not any(h["rule"] == rule for h in hits):
            continue
        if hits_only and not hits:
            continue
        if q:
            haystack = " ".join([
                p["src"], p["dst"], p["info"], p["proto"],
                str(p["sport"] or ""), str(p["dport"] or ""),
                *[h["verdict"] for h in hits],
            ]).lower()
            if q not in haystack:
                continue
        yield p, hits


@app.get("/api/packets")
def list_packets(
    session_id: str,
    offset: int = 0,
    limit: int = 200,
    proto: str = "",
    rule: str = "",
    q: str = "",
    hits_only: bool = False,
):
    entry = sessions.get(session_id)
    if entry is None:
        raise HTTPException(404, "会话不存在或已过期，请重新上传")
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    rows = []
    total = 0
    for p, hits in _filtered_rows(entry, proto, rule, q, hits_only):
        if total >= offset and len(rows) < limit:
            row = {k: v for k, v in p.items() if k != "payload_preview"}
            row["hits"] = hits
            rows.append(row)
        total += 1
    return {"total": total, "offset": offset, "limit": limit, "packets": rows}


@app.get("/api/packets/{session_id}/{no}")
def packet_detail(session_id: str, no: int):
    entry = sessions.get(session_id)
    if entry is None:
        raise HTTPException(404, "会话不存在或已过期，请重新上传")
    p = next((x for x in entry["packets"] if x["no"] == no), None)
    if p is None:
        raise HTTPException(404, f"报文 #{no} 不存在")
    detail = dict(p)
    detail["hits"] = entry["hits"].get(no, [])
    return detail


@app.post("/api/ai/analyze")
async def ai_analyze(body: AnalyzeIn):
    entry = sessions.get(body.session_id)
    if entry is None:
        raise HTTPException(404, "会话不存在或已过期，请重新上传")
    if body.scope == "packets" and not body.packet_nos:
        raise HTTPException(400, "请在报文列表中勾选要分析的报文")
    if body.scope == "flow" and not body.flow_key:
        raise HTTPException(400, "请先点击一个报文以确定要分析的流")
    context = ai.build_context(entry, body.scope, body.packet_nos, body.flow_key)
    messages = [
        {"role": "system", "content": ai.SYSTEM_PROMPT},
        {"role": "user", "content": f"请分析以下抓包数据（JSON）：\n{context}"},
    ]

    async def event_stream():
        try:
            async for delta in ai.stream_chat(messages):
                yield f"data: {json.dumps({'delta': delta}, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"
        except (ai.AIConfigError, ai.AIUpstreamError) as exc:
            yield f"data: {json.dumps({'error': str(exc)}, ensure_ascii=False)}\n\n"
        except Exception as exc:  # noqa: BLE001
            yield f"data: {json.dumps({'error': f'AI 调用失败: {exc}'}, ensure_ascii=False)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/offline-report")
def offline_report(body: ReportIn):
    entry = sessions.get(body.session_id)
    if entry is None:
        raise HTTPException(404, "会话不存在或已过期，请重新上传")
    if body.scope == "packets" and not body.packet_nos:
        raise HTTPException(400, "请在报文列表中勾选要分析的报文")
    if body.scope == "flow" and not body.flow_key:
        raise HTTPException(400, "请先点击一个报文以确定要分析的流")
    try:
        markdown = report_mod.build_report(
            entry, body.scope, body.packet_nos, body.flow_key
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"markdown": markdown, "generated_by": "local-rules"}


@app.post("/api/offline-probe-report")
def offline_probe_report(body: probes.ProbeAnalyzeIn):
    try:
        markdown = report_mod.build_probe_report(
            body.probe_type, body.summary, body.results
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"markdown": markdown, "generated_by": "local-rules"}


@app.post("/api/security/exposure/run")
async def exposure_run(body: security.ExposureRunIn):
    async def event_stream():
        try:
            async for event in security.run_exposure(body):
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as exc:  # noqa: BLE001
            yield f"data: {json.dumps({'type': 'error', 'message': f'扫描失败: {exc}'}, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/offline-exposure-report")
def offline_exposure_report(body: security.ExposureAnalyzeIn):
    markdown = report_mod.build_exposure_report(body.summary, body.assets, body.findings)
    return {"markdown": markdown, "generated_by": "local-rules"}


@app.post("/api/ai/analyze-exposure")
async def ai_analyze_exposure(body: security.ExposureAnalyzeIn):
    context = ai.build_exposure_context(body.summary, body.assets, body.findings)
    messages = [
        {"role": "system", "content": ai.SECURITY_EXPOSURE_SYSTEM_PROMPT},
        {"role": "user", "content": f"请分析以下暴露面扫描结果（JSON）：\n{context}"},
    ]

    async def event_stream():
        try:
            async for delta in ai.stream_chat(messages):
                yield f"data: {json.dumps({'delta': delta}, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"
        except (ai.AIConfigError, ai.AIUpstreamError) as exc:
            yield f"data: {json.dumps({'error': str(exc)}, ensure_ascii=False)}\n\n"
        except Exception as exc:  # noqa: BLE001
            yield f"data: {json.dumps({'error': f'AI 调用失败: {exc}'}, ensure_ascii=False)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/security/config-audit/upload")
async def config_audit_upload(file: UploadFile = File(...)):
    suffix = Path(file.filename or "config.txt").suffix.lower()
    allowed = {".txt", ".log", ".cfg", ".conf"}
    if suffix not in allowed:
        raise HTTPException(400, "支持上传 .txt、.log、.cfg 或 .conf 文本配置")
    data = bytearray()
    try:
        while chunk := await file.read(1024 * 1024):
            data.extend(chunk)
            if len(data) > MAX_CONFIG_AUDIT_BYTES:
                raise HTTPException(413, "文件过大（上限 20MB）")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, f"读取上传文件失败: {exc}") from exc
    try:
        return await asyncio.to_thread(
            device_config.audit_upload, file.filename or "config.txt", bytes(data)
        )
    except device_config.ConfigAuditError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(500, f"配置审计失败: {exc}") from exc


@app.post("/api/ai/analyze-config-audit")
async def ai_analyze_config_audit(body: ConfigAuditAnalyzeIn):
    context = device_config.build_exposure_context(body.result)
    messages = [
        {"role": "system", "content": ai.CONFIG_AUDIT_SYSTEM_PROMPT},
        {"role": "user", "content": f"请增强解读以下配置审计结果（JSON）：\n{json.dumps(context, ensure_ascii=False)}"},
    ]

    async def event_stream():
        try:
            async for delta in ai.stream_chat(messages):
                yield f"data: {json.dumps({'delta': delta}, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"
        except (ai.AIConfigError, ai.AIUpstreamError) as exc:
            yield f"data: {json.dumps({'error': str(exc)}, ensure_ascii=False)}\n\n"
        except Exception as exc:  # noqa: BLE001
            yield f"data: {json.dumps({'error': f'AI 调用失败: {exc}'}, ensure_ascii=False)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/ai/models")
async def list_models(body: ModelScanIn):
    api_key = body.api_key
    if api_key == "__KEEP__":
        api_key = config.load().get("api_key", "")
    try:
        models = await ai.list_models(body.base_url, api_key)
    except ai.AIConfigError as exc:
        raise HTTPException(400, str(exc)) from exc
    except ai.AIUpstreamError as exc:
        raise HTTPException(502, str(exc)) from exc
    return {"models": models}


@app.post("/api/probes/run")
async def probe_run(body: probes.ProbeRunIn):
    async def event_stream():
        try:
            async for event in probes.run_probe(body):
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"
        except Exception as exc:  # noqa: BLE001
            yield f"data: {json.dumps({'type': 'error', 'message': f'探测失败: {exc}'}, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/api/ai/analyze-probe")
async def ai_analyze_probe(body: probes.ProbeAnalyzeIn):
    context = ai.build_probe_context(body.probe_type, body.summary, body.results)
    messages = [
        {"role": "system", "content": ai.PROBE_SYSTEM_PROMPT},
        {"role": "user", "content": f"请分析以下网络探测结果（JSON）：\n{context}"},
    ]

    async def event_stream():
        try:
            async for delta in ai.stream_chat(messages):
                yield f"data: {json.dumps({'delta': delta}, ensure_ascii=False)}\n\n"
            yield "data: [DONE]\n\n"
        except (ai.AIConfigError, ai.AIUpstreamError) as exc:
            yield f"data: {json.dumps({'error': str(exc)}, ensure_ascii=False)}\n\n"
        except Exception as exc:  # noqa: BLE001
            yield f"data: {json.dumps({'error': f'AI 调用失败: {exc}'}, ensure_ascii=False)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/api/config")
def read_config():
    cfg = config.load()
    return {
        "base_url": cfg["base_url"],
        "model": cfg["model"],
        "api_key_masked": config.mask_key(cfg["api_key"]),
        "has_key": bool(cfg["api_key"]),
    }


@app.put("/api/config")
def write_config(body: ConfigIn):
    update = {"base_url": body.base_url, "model": body.model}
    if body.api_key == "__KEEP__":
        pass
    else:
        update["api_key"] = body.api_key or ""
    try:
        saved = config.save(update)
    except RuntimeError as exc:
        raise HTTPException(500, str(exc)) from exc
    return {
        "base_url": saved["base_url"],
        "model": saved["model"],
        "api_key_masked": config.mask_key(saved["api_key"]),
        "has_key": bool(saved["api_key"]),
    }


def _static_dir() -> Path | None:
    if getattr(sys, "frozen", False):
        bundled = Path(getattr(sys, "_MEIPASS", "")) / "static"
        if bundled.exists():
            return bundled
    dev = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    if dev.exists():
        return dev
    return None


_STATIC = _static_dir()
if _STATIC and (_STATIC / "assets").exists():
    app.mount("/assets", StaticFiles(directory=_STATIC / "assets"), name="assets")


@app.get("/{full_path:path}", include_in_schema=False)
def spa(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(404, "接口不存在")
    if _STATIC is None:
        raise HTTPException(404, "前端资源未构建，请先执行 npm run build")
    candidate = (_STATIC / full_path).resolve()
    if full_path and candidate.is_file() and candidate.is_relative_to(_STATIC.resolve()):
        return FileResponse(candidate)
    return FileResponse(_STATIC / "index.html")
