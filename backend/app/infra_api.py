"""FastAPI routes for infrastructure operations, diagnostics and knowledge."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import ai_providers, diagnostics, knowledge, network_planner, server_ops
from .infra_store import store, utc_now
from .jobs import manager
from .platform_security import (
    delete_windows_credential, redact_text, write_windows_credential,
)


router = APIRouter()
_ssh_tickets: dict[str, dict[str, Any]] = {}


class CredentialIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["password", "private_key", "passphrase", "api_key"]
    secret: str = Field(min_length=1, max_length=2_000_000)
    metadata: dict[str, Any] = {}


class CredentialUpdateIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["password", "private_key", "passphrase", "api_key"]
    secret: Optional[str] = Field(default=None, max_length=2_000_000)
    metadata: dict[str, Any] = {}


class ServerIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=253)
    os_hint: Literal["linux", "windows", "unknown"] = "linux"
    environment: str = Field(default="", max_length=80)
    tags: list[str] = Field(default=[], max_length=32)
    remark: str = Field(default="", max_length=1000)


class ConnectionIn(BaseModel):
    server_id: int
    protocol: Literal["ssh", "rdp"]
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    username: str = Field(default="", max_length=128)
    domain: str = Field(default="", max_length=128)
    auth_method: Literal["password", "key", "none"] = "password"
    credential_id: Optional[int] = None
    private_key_id: Optional[int] = None
    passphrase_id: Optional[int] = None
    jump_connection_id: Optional[int] = None
    allow_sudo: bool = False
    settings: dict[str, Any] = {}


class ConnectionTestIn(BaseModel):
    trust_host_key: bool = False


class InspectionIn(BaseModel):
    server_id: int
    profiles: list[str] = ["basic", "storage", "network", "services", "security", "containers"]
    trust_host_key: bool = False


class InspectionTaskIn(BaseModel):
    server_id: int
    name: str = Field(min_length=1, max_length=80)
    profiles: list[str] = ["basic", "storage", "network", "services", "security", "containers"]
    interval_seconds: int = Field(default=1800, ge=300, le=2_592_000)
    enabled: bool = True


class DiagnosticPlanIn(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    target_type: Literal["temporary", "server"] = "temporary"
    options: dict[str, Any] = {}


class ProviderIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    provider_type: Literal["openai_compatible", "ollama"]
    base_url: str = Field(min_length=1, max_length=2048)
    chat_model: str = Field(default="", max_length=200)
    embedding_model: str = Field(default="", max_length=200)
    api_key_credential_id: Optional[int] = None
    active: bool = False


class ContextPreviewIn(BaseModel):
    query: str = Field(min_length=1, max_length=8000)
    provider_id: Optional[int] = None
    mask_private_ips: bool = True


class AssistantMessageIn(BaseModel):
    preview_id: str
    confirmed: bool = False
    conversation_id: Optional[int] = None


class NetworkRequirementIn(BaseModel):
    name: str = Field(default="", max_length=80)
    vlan: int = Field(ge=1, le=4094)
    hosts: int = Field(ge=1, le=16_777_216)
    prefix: int | str | None = None
    purpose: str = Field(default="", max_length=160)


class NetworkPlanIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    base_cidr: str = Field(min_length=1, max_length=32)
    requirements: list[NetworkRequirementIn] = Field(min_length=1, max_length=256)
    notes: str = Field(default="", max_length=1000)


class NetworkAiPreviewIn(BaseModel):
    query: str = Field(default="请审核这份 IP 与 VLAN 规划，指出容量、掩码和网关方面的风险，并给出优化建议。", max_length=8000)
    provider_id: Optional[int] = None
    mask_private_ips: bool = True


class NetworkDraftPreviewIn(BaseModel):
    prompt: str = Field(min_length=1, max_length=8000)
    base_cidr: Optional[str] = Field(default=None, max_length=32)
    provider_id: Optional[int] = None
    mask_private_ips: bool = True


class NetworkDraftConfirmIn(BaseModel):
    preview_id: str = Field(min_length=1, max_length=128)
    confirmed: bool = False


# credentials
@router.get("/api/vault/credentials")
def credentials_list():
    return {"credentials": store.list_credentials()}


@router.post("/api/vault/credentials")
def credentials_create(body: CredentialIn):
    try:
        return store.create_credential(body.name, body.kind, body.secret, body.metadata)
    except Exception as exc:
        raise HTTPException(409, redact_text(str(exc))) from exc


@router.put("/api/vault/credentials/{credential_id}")
def credentials_update(credential_id: int, body: CredentialUpdateIn):
    try:
        return store.update_credential(credential_id, body.name, body.kind, body.secret, body.metadata)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(409, redact_text(str(exc))) from exc


@router.delete("/api/vault/credentials/{credential_id}")
def credentials_delete(credential_id: int):
    if not store.query_one("SELECT id FROM credential WHERE id=?", (credential_id,)):
        raise HTTPException(404, "凭据不存在")
    store.execute("DELETE FROM credential WHERE id=?", (credential_id,))
    return {"ok": True}


# servers and connections
@router.get("/api/ops/servers")
def servers_list():
    return {"servers": store.list_servers()}


@router.post("/api/ops/servers")
def servers_create(body: ServerIn):
    try:
        return store.save_server(body.model_dump())
    except Exception as exc:
        raise HTTPException(409, redact_text(str(exc))) from exc


@router.put("/api/ops/servers/{server_id}")
def servers_update(server_id: int, body: ServerIn):
    try:
        return store.save_server(body.model_dump(), server_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(409, redact_text(str(exc))) from exc


@router.delete("/api/ops/servers/{server_id}")
def servers_delete(server_id: int):
    if not store.get_server(server_id):
        raise HTTPException(404, "服务器不存在")
    store.execute("DELETE FROM server_profile WHERE id=?", (server_id,))
    return {"ok": True}


@router.get("/api/ops/connections")
def connections_list(server_id: int | None = None):
    return {"connections": store.list_connections(server_id)}


@router.post("/api/ops/connections")
def connections_create(body: ConnectionIn):
    try:
        return store.save_connection(body.model_dump())
    except Exception as exc:
        raise HTTPException(409, redact_text(str(exc))) from exc


@router.put("/api/ops/connections/{connection_id}")
def connections_update(connection_id: int, body: ConnectionIn):
    try:
        return store.save_connection(body.model_dump(), connection_id)
    except Exception as exc:
        raise HTTPException(409, redact_text(str(exc))) from exc


@router.delete("/api/ops/connections/{connection_id}")
def connections_delete(connection_id: int, remove_rdp_credential: bool = False):
    conn = store.get_connection(connection_id)
    if not conn:
        raise HTTPException(404, "连接不存在")
    if remove_rdp_credential and conn["protocol"] == "rdp":
        delete_windows_credential(f"TERMSRV/{conn['host']}")
    store.execute("DELETE FROM connection_profile WHERE id=?", (connection_id,))
    return {"ok": True}


@router.post("/api/ops/connections/{connection_id}/test")
def connection_test(connection_id: int, body: ConnectionTestIn):
    conn = store.get_connection(connection_id)
    if not conn:
        raise HTTPException(404, "连接不存在")
    if conn["protocol"] == "rdp":
        try:
            with __import__("socket").create_connection((conn["host"], int(conn["port"])), timeout=4):
                return {"ok": True, "message": "RDP 端口可达"}
        except OSError as exc:
            return {"ok": False, "message": redact_text(str(exc))}
    return server_ops.test_connection(connection_id, body.trust_host_key)


@router.post("/api/ops/connections/{connection_id}/launch")
def connection_launch(connection_id: int):
    conn = store.get_connection(connection_id)
    if not conn:
        raise HTTPException(404, "连接不存在")
    if conn["protocol"] != "rdp":
        raise HTTPException(400, "仅 RDP 连接可由系统客户端启动")
    username = f"{conn['domain']}\\{conn['username']}" if conn.get("domain") else conn.get("username", "")
    if conn.get("settings", {}).get("save_password") and conn.get("credential_id"):
        write_windows_credential(f"TERMSRV/{conn['host']}", username, store.get_secret(conn["credential_id"]))
    address = f"{conn['host']}:{conn['port']}"
    saved_password = bool(conn.get("settings", {}).get("save_password") and conn.get("credential_id"))
    lines = [
        f"full address:s:{address}",
        f"username:s:{username}",
        f"prompt for credentials:i:{0 if saved_password else 1}",
    ]
    fd, temp_name = tempfile.mkstemp(prefix="packet-lens-", suffix=".rdp")
    os.close(fd)
    path = Path(temp_name)
    path.write_text("\r\n".join(lines), encoding="utf-8")
    try:
        subprocess.Popen(["mstsc.exe", str(path)])
    except OSError as exc:
        path.unlink(missing_ok=True)
        raise HTTPException(500, f"无法启动 mstsc.exe：{exc}") from exc
    threading.Timer(30, lambda: path.unlink(missing_ok=True)).start()
    return {"ok": True, "message": "已启动远程桌面"}


@router.post("/api/ops/inspections")
async def inspections_create(body: InspectionIn):
    async def run(emit):
        return await asyncio.to_thread(
            server_ops.run_inspection, body.server_id, body.profiles, "manual", body.trust_host_key
        )
    try:
        return manager.create("server_inspection", f"server:{body.server_id}", run)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/api/ops/inspections")
def inspections_list(server_id: int | None = None, limit: int = 50):
    return {"runs": server_ops.list_inspections(server_id, limit)}


@router.get("/api/ops/inspections/{run_id}")
def inspections_detail(run_id: int):
    try:
        return server_ops.inspection_run(run_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/api/ops/inspection-tasks")
def inspection_tasks_list():
    return {"tasks": server_ops.list_tasks()}


@router.post("/api/ops/inspection-tasks")
def inspection_tasks_create(body: InspectionTaskIn):
    try:
        return server_ops.save_task(**body.model_dump())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.put("/api/ops/inspection-tasks/{task_id}")
def inspection_tasks_update(task_id: int, body: InspectionTaskIn):
    try:
        return server_ops.save_task(**body.model_dump(), task_id=task_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.delete("/api/ops/inspection-tasks/{task_id}")
def inspection_tasks_delete(task_id: int):
    store.execute("DELETE FROM inspection_task WHERE id=?", (task_id,))
    return {"ok": True}


# diagnostics
@router.post("/api/diagnostics/plans")
def diagnostic_plan_create(body: DiagnosticPlanIn):
    try:
        return diagnostics.create_plan(body.target, body.target_type, body.options)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/api/diagnostics/plans/{plan_id}/run")
async def diagnostic_plan_run(plan_id: int):
    async def run(emit):
        return await asyncio.to_thread(diagnostics.run_plan, plan_id, emit)
    try:
        plan = diagnostics.get_plan(plan_id)
        return manager.create("diagnostic", f"diagnostic:{plan['target']}", run)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get("/api/diagnostics/runs")
def diagnostic_runs(limit: int = 50):
    return {"runs": diagnostics.list_runs(limit)}


@router.get("/api/diagnostics/runs/{run_id}")
def diagnostic_run_detail(run_id: int):
    try:
        return diagnostics.get_run(run_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


# IP / VLAN planning
@router.get("/api/network/plans")
def network_plans_list():
    return {"plans": network_planner.list_plans()}


@router.post("/api/network/plans")
def network_plans_create(body: NetworkPlanIn):
    try:
        return network_planner.save_plan(body.name, body.base_cidr,
                                         [item.model_dump() for item in body.requirements], body.notes)
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.put("/api/network/plans/{plan_id}")
def network_plans_update(plan_id: int, body: NetworkPlanIn):
    try:
        return network_planner.save_plan(body.name, body.base_cidr,
                                         [item.model_dump() for item in body.requirements], body.notes, plan_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/api/network/plans/{plan_id}")
def network_plan_detail(plan_id: int):
    try:
        return network_planner.get_plan(plan_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.delete("/api/network/plans/{plan_id}")
def network_plans_delete(plan_id: int):
    try:
        network_planner.get_plan(plan_id)
    except ValueError:
        raise HTTPException(404, "网络规划不存在")
    store.execute("DELETE FROM network_plan WHERE id=?", (plan_id,))
    return {"ok": True}


@router.post("/api/network/plans/{plan_id}/ai-preview")
async def network_plan_ai_preview(plan_id: int, body: NetworkAiPreviewIn):
    try:
        plan = network_planner.get_plan(plan_id)
        context = json.dumps(plan["result"], ensure_ascii=False, indent=2)
        return await ai_providers.prepare_custom_context(
            body.query, context, body.provider_id, body.mask_private_ips,
            source_title=f"IP/VLAN 规划：{plan['name']}",
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, redact_text(str(exc))) from exc


@router.post("/api/network/plans/ai-draft/preview")
async def network_ai_draft_preview(body: NetworkDraftPreviewIn):
    try:
        return await network_planner.prepare_ai_draft(
            body.prompt, body.base_cidr, body.provider_id, body.mask_private_ips,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, redact_text(str(exc))) from exc


@router.post("/api/network/plans/ai-draft/confirm")
async def network_ai_draft_confirm(body: NetworkDraftConfirmIn):
    try:
        return await network_planner.confirm_ai_draft(body.preview_id, body.confirmed)
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, redact_text(str(exc))) from exc


# jobs and events
@router.get("/api/jobs/{job_id}")
def job_detail(job_id: str):
    try:
        return manager.public(job_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.delete("/api/jobs/{job_id}")
def job_cancel(job_id: str):
    try:
        return manager.cancel(job_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/api/jobs/{job_id}/events")
async def job_events(job_id: str):
    async def stream():
        try:
            async for event in manager.events(job_id):
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        except ValueError as exc:
            yield f"data: {json.dumps({'type': 'error', 'message': str(exc)}, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream")


@router.get("/api/events")
def events_list(status: str = "open", limit: int = 100):
    query = "SELECT * FROM event"
    params: list[Any] = []
    if status:
        query += " WHERE status=?"
        params.append(status)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(limit, 500)))
    return {"events": store.query(query, tuple(params))}


@router.patch("/api/events/{event_id}/ack")
def event_ack(event_id: int):
    store.execute("UPDATE event SET status='acknowledged',acknowledged_at=? WHERE id=?", (utc_now(), event_id))
    return {"ok": True}


# knowledge and assistant
@router.get("/api/knowledge/documents")
def documents_list():
    return {"documents": knowledge.list_documents()}


@router.post("/api/knowledge/documents")
async def documents_upload(file: UploadFile = File(...)):
    data = await file.read(knowledge.MAX_DOCUMENT_BYTES + 1)
    try:
        return await asyncio.to_thread(knowledge.import_document, file.filename or "document.txt", data)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.delete("/api/knowledge/documents/{document_id}")
def documents_delete(document_id: int):
    try:
        knowledge.delete_document(document_id)
        return {"ok": True}
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@router.get("/api/knowledge/search")
def knowledge_search(q: str, limit: int = 8):
    return {"results": knowledge.search(q, limit)}


@router.get("/api/ai/providers")
def providers_list():
    return {"providers": ai_providers.list_providers()}


@router.post("/api/ai/providers")
def providers_create(body: ProviderIn):
    try:
        return ai_providers.save_provider(body.model_dump())
    except Exception as exc:
        raise HTTPException(409, redact_text(str(exc))) from exc


@router.put("/api/ai/providers/{provider_id}")
def providers_update(provider_id: int, body: ProviderIn):
    try:
        return ai_providers.save_provider(body.model_dump(), provider_id)
    except Exception as exc:
        raise HTTPException(409, redact_text(str(exc))) from exc


@router.delete("/api/ai/providers/{provider_id}")
def providers_delete(provider_id: int):
    store.execute("DELETE FROM ai_provider WHERE id=?", (provider_id,))
    return {"ok": True}


@router.post("/api/assistant/context-preview")
async def assistant_preview(body: ContextPreviewIn):
    try:
        return await ai_providers.prepare_context(
            body.query, body.provider_id, body.mask_private_ips
        )
    except Exception as exc:
        raise HTTPException(400, redact_text(str(exc))) from exc


@router.post("/api/assistant/conversations/messages")
async def assistant_message(body: AssistantMessageIn):
    async def stream():
        try:
            async for delta in ai_providers.stream_assistant(
                body.preview_id, body.confirmed, body.conversation_id
            ):
                yield f"data: {json.dumps({'delta': delta}, ensure_ascii=False)}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'error': redact_text(str(exc))}, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"
    return StreamingResponse(stream(), media_type="text/event-stream")


# interactive SSH: tickets expire quickly and terminal content is never persisted
@router.post("/api/ops/ssh/sessions")
def ssh_session_create(connection_id: int, trust_host_key: bool = False):
    conn = store.get_connection(connection_id)
    if not conn or conn["protocol"] != "ssh":
        raise HTTPException(404, "SSH 连接不存在")
    ticket = secrets.token_urlsafe(24)
    _ssh_tickets[ticket] = {"connection_id": connection_id, "trust": trust_host_key, "expires": time.time() + 60}
    return {"ticket": ticket, "expires_in": 60}


@router.websocket("/ws/ssh/{ticket}")
async def ssh_websocket(websocket: WebSocket, ticket: str):
    info = _ssh_tickets.pop(ticket, None)
    if not info or info["expires"] < time.time():
        await websocket.close(code=4401, reason="连接票据无效或已过期")
        return
    await websocket.accept()
    client = channel = None
    try:
        client = await asyncio.to_thread(server_ops.connect_ssh, info["connection_id"], info["trust"])
        channel = await asyncio.to_thread(client.invoke_shell, term="xterm-256color", width=120, height=32)

        async def reader():
            while not channel.closed:
                data = await asyncio.to_thread(channel.recv, 32768)
                if not data:
                    break
                await websocket.send_text(json.dumps({"type": "output", "data": data.decode("utf-8", "replace")}))

        async def writer():
            while True:
                raw = await websocket.receive_text()
                message = json.loads(raw)
                if message.get("type") == "input":
                    await asyncio.to_thread(channel.send, str(message.get("data", "")))
                elif message.get("type") == "resize":
                    await asyncio.to_thread(channel.resize_pty, width=max(20, min(int(message.get("cols", 120)), 400)),
                                            height=max(5, min(int(message.get("rows", 32)), 200)))

        tasks = [asyncio.create_task(reader()), asyncio.create_task(writer())]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await websocket.send_text(json.dumps({"type": "error", "message": redact_text(str(exc))}))
        except Exception:
            pass
    finally:
        if channel:
            channel.close()
        if client:
            server_ops.close_ssh(client)
        try:
            await websocket.close()
        except Exception:
            pass
