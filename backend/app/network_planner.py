"""IPv4 subnet and VLAN planning helpers."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import secrets
import time
from typing import Any

from .infra_store import OpsStore, store, utc_now

_draft_previews: dict[str, dict[str, Any]] = {}


def _network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError("基础网段必须是有效的 IPv4 CIDR") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("暂只支持 IPv4 网段")
    if not 8 <= network.prefixlen <= 30:
        raise ValueError("规划掩码必须在 /8 到 /30 之间")
    return network


def plan_subnets(base_cidr: str, requirements: list[dict[str, Any]]) -> dict[str, Any]:
    base = _network(base_cidr)
    if not requirements:
        raise ValueError("至少添加一个 VLAN 需求")
    if len(requirements) > 256:
        raise ValueError("单次最多规划 256 个 VLAN")

    normalized: list[dict[str, Any]] = []
    seen_vlans: set[int] = set()
    for index, item in enumerate(requirements, 1):
        name = str(item.get("name") or f"VLAN {index}").strip()
        if not name or len(name) > 80:
            raise ValueError(f"第 {index} 行 VLAN 名称无效")
        try:
            vlan = int(item.get("vlan"))
            hosts = int(item.get("hosts"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"第 {index} 行 VLAN ID 和主机数必须是整数") from exc
        if not 1 <= vlan <= 4094:
            raise ValueError(f"第 {index} 行 VLAN ID 必须在 1-4094 之间")
        if vlan in seen_vlans:
            raise ValueError(f"VLAN {vlan} 重复")
        seen_vlans.add(vlan)
        if hosts < 1 or hosts > 2**24:
            raise ValueError(f"第 {index} 行主机数必须在 1-16777216 之间")
        requested = item.get("prefix")
        prefix = None if requested in (None, "", "auto") else int(requested)
        if prefix is not None and not 8 <= prefix <= 30:
            raise ValueError(f"第 {index} 行掩码必须在 /8 到 /30 之间")
        if prefix is not None and prefix < base.prefixlen:
            raise ValueError(f"第 {index} 行 /{prefix} 超出基础网段 {base} 的范围")
        needed = max(2, hosts + 2)
        auto_prefix = 32 - math.ceil(math.log2(needed))
        prefix = max(base.prefixlen, prefix if prefix is not None else auto_prefix)
        capacity = (1 << (32 - prefix)) - 2
        if capacity < hosts:
            raise ValueError(f"第 {index} 行 /{prefix} 无法容纳 {hosts} 台主机")
        normalized.append({"name": name, "vlan": vlan, "hosts": hosts, "prefix": prefix,
                           "purpose": str(item.get("purpose") or "").strip()[:160]})

    # VLSM: allocate the largest blocks first, keeping deterministic input order for ties.
    ordered = sorted(enumerate(normalized), key=lambda pair: (pair[1]["prefix"], pair[0]))
    cursor = int(base.network_address)
    results: list[dict[str, Any] | None] = [None] * len(normalized)
    for original_index, item in ordered:
        block_size = 1 << (32 - item["prefix"])
        start = ((cursor + block_size - 1) // block_size) * block_size
        subnet = ipaddress.ip_network(f"{ipaddress.IPv4Address(start)}/{item['prefix']}")
        if subnet.network_address < base.network_address or subnet.broadcast_address > base.broadcast_address:
            raise ValueError(f"基础网段空间不足，无法分配 VLAN {item['vlan']}")
        usable = max(0, subnet.num_addresses - 2)
        first_usable = subnet.network_address + 1 if usable else None
        last_usable = subnet.broadcast_address - 1 if usable else None
        results[original_index] = {
            **item,
            "cidr": str(subnet),
            "network": str(subnet.network_address),
            "broadcast": str(subnet.broadcast_address),
            "gateway": str(first_usable) if first_usable else "",
            "first_usable": str(first_usable) if first_usable else "",
            "last_usable": str(last_usable) if last_usable else "",
            "usable_hosts": usable,
            "utilization_percent": round(item["hosts"] / usable * 100, 2) if usable else 100,
        }
        cursor = int(subnet.broadcast_address) + 1

    allocated = sum(1 << (32 - int(item["prefix"])) for item in normalized)
    return {
        "base_cidr": str(base),
        "base_hosts": max(0, base.num_addresses - 2),
        "allocated_addresses": allocated,
        "free_addresses": max(0, base.num_addresses - allocated),
        "subnets": results,
    }


def save_plan(name: str, base_cidr: str, requirements: list[dict[str, Any]], notes: str = "",
              plan_id: int | None = None, ops_store: OpsStore = store) -> dict[str, Any]:
    name = name.strip()
    if not name or len(name) > 100:
        raise ValueError("规划名称不能为空且不能超过 100 个字符")
    result = plan_subnets(base_cidr, requirements)
    now = utc_now()
    values = (name, result["base_cidr"], json.dumps(requirements, ensure_ascii=False),
              json.dumps(result, ensure_ascii=False), notes[:1000])
    if plan_id is None:
        plan_id = ops_store.execute(
            "INSERT INTO network_plan(name,base_cidr,requirements_json,result_json,notes,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?)", values + (now, now),
        )
    else:
        if not ops_store.query_one("SELECT id FROM network_plan WHERE id=?", (plan_id,)):
            raise ValueError("网络规划不存在")
        ops_store.execute(
            "UPDATE network_plan SET name=?,base_cidr=?,requirements_json=?,result_json=?,notes=?,updated_at=? WHERE id=?",
            values + (now, plan_id),
        )
    return get_plan(plan_id, ops_store)


def get_plan(plan_id: int, ops_store: OpsStore = store) -> dict[str, Any]:
    row = ops_store.query_one("SELECT * FROM network_plan WHERE id=?", (plan_id,))
    if not row:
        raise ValueError("网络规划不存在")
    row["requirements"] = json.loads(row.pop("requirements_json") or "[]")
    row["result"] = json.loads(row.pop("result_json") or "{}")
    return row


def list_plans(ops_store: OpsStore = store) -> list[dict[str, Any]]:
    return [get_plan(int(row["id"]), ops_store) for row in ops_store.query("SELECT id FROM network_plan ORDER BY updated_at DESC")]


async def prepare_ai_draft(prompt: str, base_cidr: str | None = None,
                           provider_id: int | None = None, mask_private_ips: bool = True,
                           ops_store: OpsStore = store) -> dict[str, Any]:
    from . import ai_providers
    provider = ai_providers._provider(provider_id, ops_store)
    context = f"用户 IP/VLAN 规划需求：\n{prompt.strip()}\n"
    if base_cidr:
        context += f"基础网段候选：{base_cidr.strip()}\n"
    context += "请只返回规划草案，不执行任何网络操作。"
    from .platform_security import redact_text
    safe_context = redact_text(context, mask_private_ips)
    preview_id = secrets.token_urlsafe(18)
    _draft_previews[preview_id] = {"prompt": prompt.strip(), "base_cidr": base_cidr,
                                   "context": safe_context, "provider_id": provider["id"],
                                   "expires": time.time() + 600}
    return {"preview_id": preview_id, "provider": {"id": provider["id"], "name": provider["name"],
            "type": provider["provider_type"]}, "requires_cloud_confirmation": provider["provider_type"] != "ollama",
            "context_preview": safe_context, "expires_in": 600}


async def confirm_ai_draft(preview_id: str, confirmed: bool, ops_store: OpsStore = store) -> dict[str, Any]:
    from . import ai_providers
    preview = _draft_previews.pop(preview_id, None)
    if not preview or preview["expires"] < time.time():
        raise ValueError("AI 规划预览已过期，请重新生成")
    provider = ai_providers._provider(preview["provider_id"], ops_store)
    if provider["provider_type"] != "ollama" and not confirmed:
        raise ValueError("发送云端 AI 前必须确认上下文预览")
    system = ("你是网络规划助手。只返回一个合法 JSON 对象，不要 Markdown，不要解释。"
              "字段必须为 name、base_cidr、requirements、notes。requirements 每项包含 name、vlan、hosts、prefix、purpose；"
              "prefix 只能是 auto 或 8 到 30 的整数。")
    text = await ai_providers.complete(provider["id"], system, preview["context"], ops_store)
    match = re.search(r"\{.*\}", text, flags=re.S)
    if not match:
        raise ValueError("AI 未返回合法 JSON 规划草案")
    try:
        draft = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise ValueError("AI 返回的规划草案不是合法 JSON") from exc
    requirements = draft.get("requirements")
    if not isinstance(requirements, list):
        raise ValueError("AI 草案缺少 requirements 列表")
    base_cidr = str(draft.get("base_cidr") or preview.get("base_cidr") or "").strip()
    result = plan_subnets(base_cidr, requirements)
    return {"name": str(draft.get("name") or "AI 网络规划")[:100], "base_cidr": result["base_cidr"],
            "requirements": requirements, "notes": str(draft.get("notes") or "")[:1000], "result": result}
