from __future__ import annotations

import json
from typing import AsyncIterator

import httpx

from . import config

SYSTEM_PROMPT = (
    "你是资深网络工程师，正在帮助用户分析抓包结果。"
    "请基于给出的报文数据与规则命中情况，用中文按以下 Markdown 结构输出：\n"
    "## 现象\n（客观描述观察到的流量行为）\n"
    "## 可能原因\n（按可能性排序，结合具体报文证据）\n"
    "## 排查建议\n（给出可操作的下一步命令或检查点）\n"
    "保持简洁、可操作，直接引用报文编号作为证据。"
)

PROBE_SYSTEM_PROMPT = (
    "你是资深网络工程师，正在分析网络探测结果。"
    "请基于给出的 Ping / HTTP / TCP 端口扫描结果，用中文按以下 Markdown 结构输出：\n"
    "## 结论\n（客观概括探测成功率、异常分布和最可能的问题面）\n"
    "## 风险\n（指出可用性、连通性、TLS 或服务暴露相关的风险，按可能性排序）\n"
    "## 建议\n（给出下一步检查点、需要确认的网络/服务配置，或可执行命令）\n"
    "不要编造探测结果里不存在的端口、状态码或主机。"
)

SECURITY_EXPOSURE_SYSTEM_PROMPT = (
    "你是资深网络安全工程师，正在分析授权范围内的暴露面扫描结果。"
    "请基于给出的资产、开放端口、服务指纹、HTTP 安全头和 TLS 证书信息，用中文按以下 Markdown 结构输出：\n"
    "## 结论\n（概括资产存活情况、暴露面规模和主要风险）\n"
    "## 风险\n（按优先级列出服务暴露、TLS、HTTP 安全头等风险，不提供攻击步骤）\n"
    "## 建议\n（给出加固、访问控制、证书和服务运维建议）\n"
    "不要编造未扫描的端口或资产，不要输出利用代码或凭据猜测方法。"
)

CONFIG_AUDIT_SYSTEM_PROMPT = (
    "你是资深网络设备安全审计工程师，正在分析已经脱敏的 H3C、华为、ZTE 或锐捷配置摘要。"
    "请只基于给出的离线审计发现和脱敏证据，用中文按以下 Markdown 结构输出：\n"
    "## 结论\n（概括配置风险与设备类型适配要点）\n"
    "## 风险\n（解释为什么这些配置会造成风险，按优先级排序）\n"
    "## 建议\n（按设备厂商命令风格给出加固方向，不要要求用户提供密码，不要输出攻击步骤）\n"
    "不要尝试恢复或猜测被脱敏的凭据，不要编造配置中不存在的内容。"
)


class AIConfigError(Exception):
    pass


class AIUpstreamError(Exception):
    pass


def _row_brief(p: dict, hits: list[dict]) -> dict:
    row = {
        "no": p["no"],
        "time": p["ts"],
        "src": f"{p['src']}:{p['sport']}" if p["sport"] is not None else p["src"],
        "dst": f"{p['dst']}:{p['dport']}" if p["dport"] is not None else p["dst"],
        "proto": p["proto"],
        "info": p["info"],
        "hits": [{"rule": h["rule"], "verdict": h["verdict"]} for h in hits],
    }
    for key in ("dns", "http", "tls", "icmp"):
        if p.get(key):
            row[key] = p[key]
    return row


def build_context(entry: dict, scope: str, packet_nos: list[int] | None = None,
                  flow_key: str | None = None) -> str:
    packets = entry["packets"]
    hits = entry["hits"]
    if scope == "overview":
        hit_rows = [p for p in packets if hits.get(p["no"])][:30]
        context = {
            "文件": entry["filename"],
            "总包数": entry["packet_count"],
            "已截断": entry["capped"],
            "协议分布": entry["protocols"],
            "规则命中统计": entry["rule_summary"],
            "关键流": [
                {k: v for k, v in f.items() if k != "syn_nos"}
                for f in entry["flow_stats"][:15]
            ],
            "命中示例报文": [_row_brief(p, hits.get(p["no"], [])) for p in hit_rows],
        }
    elif scope == "packets":
        nos = set(packet_nos or [])
        selected = [p for p in packets if p["no"] in nos][:50]
        context = {"选中报文": [_row_brief(p, hits.get(p["no"], [])) for p in selected]}
    else:
        rows = [p for p in packets if p["flow"] == flow_key][:100]
        flow_stat = next((f for f in entry["flow_stats"] if f["flow"] == flow_key), None)
        context = {
            "流": flow_key,
            "流统计": flow_stat,
            "报文": [_row_brief(p, hits.get(p["no"], [])) for p in rows],
        }
    return json.dumps(context, ensure_ascii=False, separators=(",", ":"))


def build_probe_context(probe_type: str, summary: dict, results: list[dict]) -> str:
    bad_statuses = {"timeout", "unreachable", "client_error", "server_error",
                    "closed", "refused", "tls_error", "error"}
    bad = [r for r in results if r.get("ok") is False or str(r.get("status", "")).lower() in bad_statuses]
    good = [r for r in results if r not in bad]
    sample = bad[:40] + good[:10]
    context = {
        "probe_type": probe_type,
        "summary": summary,
        "异常与代表性结果": sample,
    }
    return json.dumps(context, ensure_ascii=False, separators=(",", ":"))


def build_exposure_context(summary: dict, assets: list[dict],
                           findings: list[dict]) -> str:
    risky = [
        item for item in findings
        if str(item.get("severity", "")).lower() in {"critical", "high", "medium"}
    ]
    low = [item for item in findings if item not in risky]
    context = {
        "summary": summary,
        "代表性资产": assets[:50],
        "重点风险": risky[:50],
        "低风险发现": low[:20],
    }
    return json.dumps(context, ensure_ascii=False, separators=(",", ":"))


async def list_models(base_url: str, api_key: str) -> list[str]:
    if not base_url:
        raise AIConfigError("请先填写 Base URL")
    url = base_url.rstrip("/") + "/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(15)) as client:
            resp = await client.get(url, headers=headers)
    except httpx.HTTPError as exc:
        raise AIUpstreamError(f"模型列表连接失败: {exc}") from exc
    if resp.status_code != 200:
        body = resp.text[:300]
        raise AIUpstreamError(f"模型列表返回 {resp.status_code}: {body}")
    try:
        payload = resp.json()
    except ValueError:
        raise AIUpstreamError("模型列表返回的不是 JSON")

    items: list = []
    if isinstance(payload, dict):
        items = payload.get("data") or payload.get("models") or []
    elif isinstance(payload, list):
        items = payload

    models = []
    seen = set()
    for item in items:
        model_id = item if isinstance(item, str) else (item or {}).get("id")
        if model_id and model_id not in seen:
            seen.add(model_id)
            models.append(str(model_id))
    if not models:
        raise AIUpstreamError("模型列表返回为空或格式不兼容")
    return models


async def stream_chat(messages: list[dict]) -> AsyncIterator[str]:
    cfg = config.load()
    if not cfg.get("api_key"):
        raise AIConfigError("尚未配置 AI API Key，请点击右上角设置进行配置")
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    payload = {
        "model": cfg["model"],
        "messages": messages,
        "stream": True,
        "temperature": 0.3,
    }
    headers = {"Authorization": f"Bearer {cfg['api_key']}"}
    timeout = httpx.Timeout(connect=10, read=180, write=30, pool=30)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("POST", url, json=payload, headers=headers) as resp:
                if resp.status_code != 200:
                    body = (await resp.aread()).decode("utf-8", "replace")[:300]
                    raise AIUpstreamError(f"AI 接口返回 {resp.status_code}: {body}")
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        obj = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    delta = (obj.get("choices") or [{}])[0].get("delta", {}).get("content")
                    if delta:
                        yield delta
    except httpx.HTTPError as exc:
        raise AIUpstreamError(f"AI 接口连接失败: {exc}") from exc
