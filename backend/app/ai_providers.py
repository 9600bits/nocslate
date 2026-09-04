"""Multi-provider chat/embedding adapters and privacy-gated knowledge context."""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, AsyncIterator

import httpx

from .infra_store import OpsStore, store, utc_now
from .knowledge import search
from .platform_security import redact_text


_previews: dict[str, dict[str, Any]] = {}


def list_providers(ops_store: OpsStore = store) -> list[dict[str, Any]]:
    rows = ops_store.query("SELECT * FROM ai_provider ORDER BY active DESC,name")
    for row in rows:
        row["active"] = bool(row["active"])
        row["has_key"] = bool(row.pop("api_key_credential_id"))
    return rows


def save_provider(data: dict[str, Any], provider_id: int | None = None,
                  ops_store: OpsStore = store) -> dict[str, Any]:
    now = utc_now()
    active = int(bool(data.get("active", False)))
    if active:
        ops_store.execute("UPDATE ai_provider SET active=0")
    values = (
        data["name"].strip(), data["provider_type"], data["base_url"].rstrip("/"),
        data.get("chat_model", ""), data.get("embedding_model", ""),
        data.get("api_key_credential_id"), active,
    )
    if provider_id is None:
        provider_id = ops_store.execute(
            "INSERT INTO ai_provider(name,provider_type,base_url,chat_model,embedding_model,"
            "api_key_credential_id,active,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            values + (now, now),
        )
    else:
        ops_store.execute(
            "UPDATE ai_provider SET name=?,provider_type=?,base_url=?,chat_model=?,embedding_model=?,"
            "api_key_credential_id=?,active=?,updated_at=? WHERE id=?", values + (now, provider_id),
        )
    return next(item for item in list_providers(ops_store) if item["id"] == provider_id)


def _provider(provider_id: int | None, ops_store: OpsStore) -> dict[str, Any]:
    if provider_id:
        row = ops_store.query_one("SELECT * FROM ai_provider WHERE id=?", (provider_id,))
    else:
        row = ops_store.query_one("SELECT * FROM ai_provider WHERE active=1 ORDER BY id LIMIT 1")
    if not row:
        raise ValueError("尚未配置 AI 提供商")
    return row


async def embedding(provider: dict[str, Any], text: str, ops_store: OpsStore = store) -> list[float] | None:
    model = provider.get("embedding_model") or ""
    if not model:
        return None
    timeout = httpx.Timeout(30)
    async with httpx.AsyncClient(timeout=timeout) as client:
        if provider["provider_type"] == "ollama":
            response = await client.post(provider["base_url"].rstrip("/") + "/api/embed",
                                         json={"model": model, "input": text})
            response.raise_for_status()
            values = response.json().get("embeddings") or []
            return [float(value) for value in (values[0] if values else [])]
        key = ops_store.get_secret(provider.get("api_key_credential_id"))
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        response = await client.post(provider["base_url"].rstrip("/") + "/embeddings",
                                     headers=headers, json={"model": model, "input": text})
        response.raise_for_status()
        values = response.json().get("data") or []
        return [float(value) for value in ((values[0] if values else {}).get("embedding") or [])]


async def prepare_context(query: str, provider_id: int | None = None, mask_private_ips: bool = True,
                          ops_store: OpsStore = store) -> dict[str, Any]:
    provider = _provider(provider_id, ops_store)
    vector = None
    try:
        vector = await embedding(provider, query, ops_store)
    except Exception:
        vector = None
    results = search(query, 8, vector, provider.get("embedding_model", ""), ops_store)
    sources = [{
        "document_id": item["document_id"], "title": item["title"],
        "source_type": item["source_type"], "source_ref": item["source_ref"],
        "updated_at": item["updated_at"], "score": item["score"],
    } for item in results]
    excerpts = [f"[来源 {index + 1}] {item['title']}\n{item['content']}"
                for index, item in enumerate(results)]
    context = redact_text("\n\n".join(excerpts), mask_private_ips)
    preview_id = secrets.token_urlsafe(18)
    _previews[preview_id] = {
        "query": query, "context": context, "sources": sources, "provider_id": provider["id"],
        "expires": time.time() + 600,
    }
    for key in list(_previews):
        if _previews[key]["expires"] < time.time():
            _previews.pop(key, None)
    return {
        "preview_id": preview_id, "provider": {"id": provider["id"], "name": provider["name"],
                                                   "type": provider["provider_type"]},
        "requires_cloud_confirmation": provider["provider_type"] != "ollama",
        "sources": sources, "context_preview": context[:12000], "expires_in": 600,
    }


async def prepare_custom_context(query: str, context: str, provider_id: int | None = None,
                                 mask_private_ips: bool = True, source_title: str = "本地规划",
                                 ops_store: OpsStore = store) -> dict[str, Any]:
    """Create the same confirmation-gated preview for generated, non-document context."""
    provider = _provider(provider_id, ops_store)
    preview_id = secrets.token_urlsafe(18)
    safe_context = redact_text(context, mask_private_ips)
    sources = [{"document_id": None, "title": source_title, "source_type": "generated",
                "source_ref": "network_plan", "updated_at": utc_now(), "score": 1.0}]
    _previews[preview_id] = {
        "query": query, "context": safe_context, "sources": sources,
        "provider_id": provider["id"], "expires": time.time() + 600,
    }
    return {
        "preview_id": preview_id,
        "provider": {"id": provider["id"], "name": provider["name"], "type": provider["provider_type"]},
        "requires_cloud_confirmation": provider["provider_type"] != "ollama",
        "sources": sources, "context_preview": safe_context[:12000], "expires_in": 600,
    }


async def complete(provider_id: int | None, system: str, user: str,
                   ops_store: OpsStore = store) -> str:
    """Run a non-streaming completion for structured workflows such as planners."""
    provider = _provider(provider_id, ops_store)
    timeout = httpx.Timeout(connect=10, read=180, write=30, pool=30)
    async with httpx.AsyncClient(timeout=timeout) as client:
        if provider["provider_type"] == "ollama":
            response = await client.post(provider["base_url"].rstrip("/") + "/api/chat", json={
                "model": provider["chat_model"], "messages": [
                    {"role": "system", "content": system}, {"role": "user", "content": user},
                ], "stream": False,
            })
            response.raise_for_status()
            return ((response.json().get("message") or {}).get("content") or "").strip()
        key = ops_store.get_secret(provider.get("api_key_credential_id"))
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        response = await client.post(provider["base_url"].rstrip("/") + "/chat/completions",
                                     headers=headers, json={"model": provider["chat_model"], "stream": False,
                                                            "temperature": 0.1, "messages": [
                                                                {"role": "system", "content": system},
                                                                {"role": "user", "content": user},
                                                            ]})
        response.raise_for_status()
        return ((response.json().get("choices") or [{}])[0].get("message") or {}).get("content", "").strip()


async def stream_assistant(preview_id: str, confirmed: bool, conversation_id: int | None = None,
                           ops_store: OpsStore = store) -> AsyncIterator[str]:
    preview = _previews.pop(preview_id, None)
    if not preview or preview["expires"] < time.time():
        raise ValueError("上下文预览已过期，请重新生成")
    provider = _provider(preview["provider_id"], ops_store)
    if provider["provider_type"] != "ollama" and not confirmed:
        raise ValueError("发送云端 AI 前必须确认上下文预览")
    if conversation_id is None:
        now = utc_now()
        conversation_id = ops_store.execute(
            "INSERT INTO assistant_conversation(title,provider_id,created_at,updated_at) VALUES(?,?,?,?)",
            (preview["query"][:80], provider["id"], now, now),
        )
    ops_store.execute(
        "INSERT INTO assistant_message(conversation_id,role,content,sources_json,created_at) VALUES(?,?,?,?,?)",
        (conversation_id, "user", preview["query"], "[]", utc_now()),
    )
    system = (
        "你是 NOCSlate 本地基础设施助手。只根据给定知识片段回答，使用中文，给出可操作建议。"
        "事实必须使用 [来源 N] 标注；资料不足时明确说明，不编造主机、端口或配置状态。"
    )
    user = f"问题：{preview['query']}\n\n可用知识：\n{preview['context'] or '没有检索到相关资料'}"
    acc = ""
    timeout = httpx.Timeout(connect=10, read=180, write=30, pool=30)
    async with httpx.AsyncClient(timeout=timeout) as client:
        if provider["provider_type"] == "ollama":
            response = await client.post(
                provider["base_url"].rstrip("/") + "/api/chat",
                json={"model": provider["chat_model"], "messages": [
                    {"role": "system", "content": system}, {"role": "user", "content": user},
                ], "stream": False},
            )
            response.raise_for_status()
            acc = ((response.json().get("message") or {}).get("content") or "").strip()
            if acc:
                yield acc
        else:
            key = ops_store.get_secret(provider.get("api_key_credential_id"))
            headers = {"Authorization": f"Bearer {key}"} if key else {}
            async with client.stream(
                "POST", provider["base_url"].rstrip("/") + "/chat/completions",
                headers=headers, json={"model": provider["chat_model"], "stream": True,
                                       "temperature": 0.2, "messages": [
                                           {"role": "system", "content": system},
                                           {"role": "user", "content": user},
                                       ]},
            ) as response:
                response.raise_for_status()
                async for line in response.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        delta = (json.loads(data).get("choices") or [{}])[0].get("delta", {}).get("content")
                    except ValueError:
                        delta = None
                    if delta:
                        acc += delta
                        yield delta
    ops_store.execute(
        "INSERT INTO assistant_message(conversation_id,role,content,sources_json,created_at) VALUES(?,?,?,?,?)",
        (conversation_id, "assistant", acc, json.dumps(preview["sources"], ensure_ascii=False), utc_now()),
    )
    ops_store.execute("UPDATE assistant_conversation SET updated_at=? WHERE id=?", (utc_now(), conversation_id))
