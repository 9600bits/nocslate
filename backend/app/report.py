from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from . import rules as rules_mod

SEVERITY_LABEL = {"error": "严重", "warning": "警告"}

RULE_REPORT = {
    "rst": {
        "title": "TCP RST / RST+ACK",
        "causes": [
            "目标端口未开放，服务端直接拒绝连接。",
            "防火墙、负载均衡或安全策略主动重置连接。",
            "应用层异常、服务进程退出或超时后由协议栈关闭连接。",
            "抓包位置位于中间设备时，RST 可能由链路中某一跳产生。",
        ],
        "actions": [
            "确认 RST 方向：服务端主动 RST 通常表示端口关闭或被策略拒绝。",
            "在目标机器用 `netstat -ano` 或 `ss -tnlp` 核对服务进程与监听端口。",
            "检查本机防火墙、云安全组和中间设备的会话超时策略。",
            "结合同一流是否完成 TCP 三次握手判断是拒绝还是中途重置。",
        ],
    },
    "retransmission": {
        "title": "TCP 重传",
        "causes": [
            "网络丢包、拥塞或中间设备静默丢弃报文。",
            "链路质量问题，例如无线信号、双工不匹配、CRC 错误或队列溢出。",
            "抓包自身丢帧时也可能造成同一数据段重复出现。",
        ],
        "actions": [
            "统计重传集中在哪条流、哪个方向，缩小问题设备范围。",
            "查看重传前后的窗口、往返时延和是否伴随零窗口。",
            "检查交换机端口错误计数、丢包计数和无线链路信号。",
            "分段抓包对比客户端侧与服务器侧是否都看到同一丢包现象。",
        ],
    },
    "zero_window": {
        "title": "TCP 零窗口",
        "causes": [
            "接收端应用处理速度跟不上，接收缓冲区被填满。",
            "应用线程阻塞、磁盘或 CPU 饱和、socket 缓冲区配置过小。",
            "对端停止读取数据，常见于慢消费或僵死进程。",
        ],
        "actions": [
            "确认零窗口报文来自服务端还是客户端，找出处理瓶颈一端。",
            "在接收端检查 CPU、内存、磁盘 IO 和进程线程状态。",
            "检查应用消费队列长度以及是否出现连接假死。",
            "必要时调整 socket 收发缓冲区或修复应用读取逻辑。",
        ],
    },
    "syn_halfopen": {
        "title": "SYN 半开",
        "causes": [
            "目标地址不可达，SYN 报文被路由丢弃或主机无响应。",
            "目标端口没有服务监听，且防火墙只丢弃 SYN 而不回 RST。",
            "目标主机防火墙策略仅允许特定来源访问。",
            "也可能是主动扫描行为，需要结合来源与端口范围判断。",
        ],
        "actions": [
            "确认目标 IP 是否可达：`ping` 与 `tracert` 或对应平台路由跟踪。",
            "在目标端确认端口监听状态和防火墙规则。",
            "观察同一来源是否向大量不同端口发送 SYN，排除扫描行为。",
            "在客户端和服务端同时抓包定位 SYN 被丢弃的位置。",
        ],
    },
    "syn_scan": {
        "title": "疑似端口扫描",
        "causes": [
            "同一来源向大量端口发送 SYN 且未建立连接，符合端口扫描特征。",
            "也可能是自动化监控、批量探测脚本或错误配置的重试逻辑。",
            "若来源是公网地址，更可能是外部扫描或恶意探测。",
        ],
        "actions": [
            "确认该来源是否属于已授权资产或已知监控系统。",
            "在边界防火墙上按来源 IP 核对扫描频率与目标端口。",
            "对来源主机进行基线检查，确认是否存在异常进程或凭据泄露。",
            "对敏感端口启用访问控制或告警规则。",
        ],
    },
    "dns_fail": {
        "title": "DNS 解析失败",
        "causes": [
            "查询域名不存在，常见于拼写错误、过期记录或动态域名失效。",
            "递归解析器无法找到上游答案，或上游服务拒绝查询。",
            "域名解析策略拦截、本地 hosts 冲突或 DNS 缓存异常。",
        ],
        "actions": [
            "记录失败域名，使用 `nslookup` 或 `dig` 直接向同一解析器复测。",
            "区分 NXDOMAIN、SERVFAIL、REFUSED 等 rcode 含义。",
            "检查域名注册状态、DNS 记录和权威服务器可达性。",
            "若为内网域名，检查内部 DNS 区域配置与同步状态。",
        ],
    },
    "http_error": {
        "title": "HTTP 错误响应",
        "causes": [
            "服务端应用返回 4xx，通常是请求、鉴权或资源路径问题。",
            "5xx 表示服务端内部错误、网关或上游依赖异常。",
            "WAF、反向代理或负载均衡拦截并返回错误页面。",
        ],
        "actions": [
            "根据状态码区分客户端错误与服务端错误。",
            "查看服务端访问日志、应用日志和错误堆栈。",
            "复现请求并核对 URL、方法、Headers 与认证信息。",
            "检查反向代理、网关和上游服务的健康状态。",
        ],
    },
    "tls_alert": {
        "title": "TLS Alert",
        "causes": [
            "证书过期、不受信任、主机名不匹配或证书链不完整。",
            "客户端与服务端协议版本或密码套件不兼容。",
            "中间设备对 TLS 流量进行检测、阻断或重置。",
            "应用主动发送 close_notify 之外的告警结束会话。",
        ],
        "actions": [
            "记录 TLS alert 的级别和描述，例如 handshake_failure、bad_certificate。",
            "检查证书有效期、颁发链、SAN 和客户端信任库。",
            "确认客户端与服务端支持的 TLS 版本和密码套件交集。",
            "若经过代理或安全设备，临时直连对比以排除中间设备干扰。",
        ],
    },
    "icmp_err": {
        "title": "ICMP 错误",
        "causes": [
            "ICMP 目标不可达，可能为主机、网络或端口不可达。",
            "ICMP 超时通常表示 TTL 耗尽，路径存在环路或跳数过多。",
            "部分网络设备会限制 ICMP 报文的发送频率。",
        ],
        "actions": [
            "结合 type/code 判断具体不可达原因。",
            "用路由跟踪定位 TTL 超时出现的设备。",
            "检查目标主机是否在线、端口是否监听、防火墙是否阻断。",
            "核对是否存在路由环路、错误静态路由或 MTU 问题。",
        ],
    },
}

SCOPE_LABELS = {
    "overview": "整体概览（全部报文）",
    "packets": "选中报文",
    "flow": "单条流",
}

PROBE_STATUS_LABELS = {
    "reachable": "可达",
    "timeout": "超时",
    "unreachable": "不可达",
    "error": "错误",
    "ok": "正常",
    "redirect": "重定向",
    "client_error": "客户端错误",
    "server_error": "服务端错误",
    "tls_error": "TLS 错误",
    "open": "开放",
    "closed": "关闭/拒绝",
}


def _cell(value: object) -> str:
    text = str(value if value is not None else "")
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _fmt_ts(ts: float) -> str:
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return f"{ts:.6f}"


def _protocol_counts(packets: list[dict]) -> dict:
    return dict(Counter(p["proto"] for p in packets))


def _severity_totals(summary: dict) -> dict:
    totals = {"error": 0, "warning": 0}
    for rule_id, count in summary.items():
        severity = rules_mod.SEVERITY_BY_RULE.get(rule_id)
        if severity in totals:
            totals[severity] += count
    return totals


def _hit_summary(hits_by_no: dict[int, list[dict]]) -> dict:
    summary = Counter()
    for hits in hits_by_no.values():
        for hit in hits:
            summary[hit["rule"]] += 1
    return dict(summary)


def _flow_table(entry: dict, rows: list[dict], limit: int = 10) -> str:
    flow_count = Counter(p["flow"] for p in rows if p["flow"])
    stats_by_flow = {f["flow"]: f for f in entry["flow_stats"]}
    candidates = [
        stats_by_flow[flow]
        for flow, _ in flow_count.most_common()
        if flow in stats_by_flow
    ]
    if not candidates:
        return ""
    lines = [
        "| 流 | 包数 | SYN | SYN-ACK | RST | FIN | 说明 |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in candidates[:limit]:
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} |".format(
                _cell(f.get("flow", "")),
                f.get("packets", 0),
                f.get("syn", 0),
                f.get("synack", 0),
                f.get("rst", 0),
                f.get("fin", 0),
                _cell(f.get("note", "")),
            )
        )
    return "\n".join(lines)


def _evidence_table(rows: list[dict], hits_by_no: dict, limit: int = 25) -> str:
    lines = [
        "| 报文 | 时间 | 源 -> 目的 | 协议 | 信息 | 命中 |",
        "|---|---|---|---|---|---|",
    ]
    for p in rows[:limit]:
        hits = hits_by_no.get(p["no"], [])
        src = p["src"]
        dst = p["dst"]
        if p.get("sport") is not None:
            src = f"{src}:{p['sport']}"
        if p.get("dport") is not None:
            dst = f"{dst}:{p['dport']}"
        verdicts = "; ".join(h["verdict"] for h in hits) or "无"
        lines.append(
            "| #{} | {} | {} -> {} | {} | {} | {} |".format(
                p["no"],
                _fmt_ts(p["ts"]),
                _cell(src),
                _cell(dst),
                _cell(p["proto"]),
                _cell(p.get("info", "")),
                _cell(verdicts),
            )
        )
    return "\n".join(lines)


def _rule_sections(summary: dict) -> str:
    sections = []
    for rule_id, count in sorted(summary.items(), key=lambda item: (-item[1], item[0])):
        info = RULE_REPORT.get(rule_id)
        rule = next((r for r in rules_mod.RULES if r["id"] == rule_id), None)
        if not info or not rule:
            continue
        sections.append(f"## 规则解读：{info['title']}")
        sections.append(f"本会话命中 **{count}** 次，级别为 **{SEVERITY_LABEL.get(rule['severity'], rule['severity'])}**。")
        sections.append("\n**可能原因**\n")
        sections.extend(f"- {cause}" for cause in info["causes"])
        sections.append("\n**排查建议**\n")
        sections.extend(f"- {action}" for action in info["actions"])
        sections.append("")
    return "\n".join(sections)


def _conclusion(summary: dict, total: int, hit_count: int) -> str:
    totals = _severity_totals(summary)
    if not summary:
        return (
            f"在本次分析的 {total} 个报文中未命中内置异常规则。"
            "该结论仅表示未观察到已知异常模式，不能证明业务正确或网络绝对安全，"
            "建议结合业务预期、服务日志和更长时段的抓包继续核对。"
        )
    parts = [f"本次分析共 {total} 个报文，命中 {hit_count} 次规则结论。"]
    if totals["error"]:
        parts.append(f"其中严重级别 {totals['error']} 次、警告级别 {totals['warning']} 次。")
        parts.append("重点优先处置严重级别命中，并沿着对应报文还原完整连接上下文。")
    elif totals["warning"]:
        parts.append(f"未发现严重级别结论，但存在 {totals['warning']} 次警告。")
        parts.append("建议按命中规则逐项核对，避免将偶发重传或 DNS 失败误判为业务故障。")
    else:
        parts.append("规则引擎未产生分级结论。")
    return "".join(parts)


def build_report(entry: dict, scope: str, packet_nos: list[int] | None = None,
                 flow_key: str | None = None) -> str:
    packets = entry["packets"]
    hits = entry["hits"]
    if scope == "packets":
        nos = set(packet_nos or [])
        rows = [p for p in packets if p["no"] in nos]
    elif scope == "flow":
        rows = [p for p in packets if p["flow"] == flow_key][:1000]
    else:
        rows = packets

    rows.sort(key=lambda p: p["no"])
    hits_by_no = {p["no"]: hits.get(p["no"], []) for p in rows}
    summary = _hit_summary(hits_by_no)
    totals = _severity_totals(summary)
    hit_count = sum(summary.values())
    protocols = _protocol_counts(rows)
    scope_label = SCOPE_LABELS.get(scope, scope)
    if scope == "packets":
        scope_label += f"（{len(rows)} 条）"
    elif scope == "flow":
        scope_label += f"：{flow_key or '未指定'}"

    times = [p["ts"] for p in rows]
    time_start = min(times) if times else None
    time_end = max(times) if times else None
    duration = (time_end - time_start) if time_start is not None and time_end is not None else None
    protocol_text = "；".join(f"{name} {count}" for name, count in protocols.items()) or "无"

    lines = [
        "# NOCSlate 离线诊断报告",
        "",
        "> 本报告由本地规则引擎生成，不依赖网络和 AI API。",
        "",
        "## 总体结论",
        "",
        _conclusion(summary, len(rows), hit_count),
        "",
        "## 数据概览",
        "",
        "| 项目 | 值 |",
        "|---|---|",
        f"| 分析范围 | {_cell(scope_label)} |",
        f"| 文件 | {_cell(entry['filename'])} |",
        f"| 报文数 | {len(rows)} / 共 {entry['packet_count']} |",
        f"| 是否截断 | {'是' if entry.get('capped') else '否'} |",
        f"| 开始时间 | {_fmt_ts(time_start) if time_start is not None else '-'} |",
        f"| 结束时间 | {_fmt_ts(time_end) if time_end is not None else '-'} |",
        f"| 时长 | {duration:.3f}s  |" if duration is not None else "| 时长 | - |",
        f"| 协议分布 | {_cell(protocol_text)} |",
        f"| 严重命中 | {totals['error']} |",
        f"| 警告命中 | {totals['warning']} |",
        f"| 命中规则数 | {len(summary)} |",
        "",
        "## 规则命中统计",
        "",
    ]
    if summary:
        lines.extend([
            "| 级别 | 规则 | 次数 | 规则说明 |",
            "|---|---|---|---|",
        ])
        for rule_id, count in sorted(summary.items(), key=lambda item: (-item[1], item[0])):
            rule = next((r for r in rules_mod.RULES if r["id"] == rule_id), None)
            if rule is None:
                continue
            lines.append(
                "| {} | {} | {} | {} |".format(
                    SEVERITY_LABEL.get(rule["severity"], rule["severity"]),
                    _cell(rule["name"]),
                    count,
                    _cell(rule["description"]),
                )
            )
    else:
        lines.append("未命中任何内置规则。")

    flow_table = _flow_table(entry, rows)
    if flow_table:
        lines.extend(["", "## 关键流", "", flow_table, ""])

    lines.extend(["", "## 重点报文证据", "", _evidence_table(rows, hits_by_no)])
    rule_text = _rule_sections(summary)
    if rule_text:
        lines.extend(["", rule_text, ""])

    lines.extend([
        "## 通用排查建议",
        "",
        "- 从最严重的命中开始，逐个还原连接的完整生命周期。",
        "- 对照目标机器的服务日志、系统日志和防火墙日志交叉验证。",
        "- 在客户端与服务端同时抓包，确认异常发生在哪一段路径。",
        "- 使用 NOCSlate 的网络探测页复核端口、HTTP 状态和链路延迟。",
        "- 重新抓包时保留更长时间窗口，避免只看到问题片段。",
        "",
        "## 局限性",
        "",
        "本报告只基于当前会话中已解析的报文和内置启发式规则。",
        "未命中的规则不代表绝对安全；加密流量无法解密时，只能观察到连接层行为。",
        "配置 AI 接口后，可以使用 AI 解读补充更贴近业务上下文的判断。",
    ])
    return "\n".join(lines) + "\n"


def _probe_status(result: dict) -> str:
    return str(result.get("category") or result.get("status") or "error")


def _probe_target(result: dict) -> str:
    return str(result.get("endpoint") or result.get("target") or result.get("final_url") or "")


def _probe_metric(result: dict, probe_type: str) -> str:
    if probe_type == "ping":
        avg = result.get("avg_ms")
        return f"{avg} ms" if avg is not None else "-"
    elapsed = result.get("elapsed_ms")
    return f"{elapsed} ms" if elapsed is not None else "-"


def _probe_result_table(results: list[dict], probe_type: str) -> str:
    lines = [
        "| 目标 | 状态 | 指标 | 说明 |",
        "|---|---|---|---|",
    ]
    for result in results:
        status = _probe_status(result)
        lines.append(
            "| {} | {} | {} | {} |".format(
                _cell(_probe_target(result)),
                _cell(PROBE_STATUS_LABELS.get(status, status)),
                _cell(_probe_metric(result, probe_type)),
                _cell(result.get("detail", "")),
            )
        )
    return "\n".join(lines)


def _probe_conclusion(probe_type: str, summary: dict, results: list[dict]) -> str:
    total = len(results)
    ok_count = int(summary.get("ok_count", 0))
    error_count = int(summary.get("error_count", 0))
    if not results:
        return "没有提供探测结果，无法生成结论。"
    if error_count == 0:
        return f"共探测 {total} 个目标/端口组合，全部判定为正常。"
    ratio = error_count / total * 100
    kind = {"ping": "连通性", "http": "HTTP 可用性", "tcp": "端口开放性"}.get(probe_type, "探测")
    return (
        f"共探测 {total} 个目标/端口组合，正常 {ok_count} 个，异常 {error_count} 个"
        f"（{ratio:.1f}%）。优先检查{kind}相关的目标、路径、防火墙和服务状态。"
    )


def _probe_risk_and_actions(probe_type: str, summary: dict, results: list[dict]) -> tuple[list[str], list[str]]:
    statuses = {str(k): int(v) for k, v in (summary.get("statuses") or {}).items()}
    risks = []
    actions = []
    if probe_type == "ping":
        if statuses.get("timeout") or statuses.get("unreachable"):
            risks.extend(["部分主机无 ICMP 应答，可能存在主机离线、路由不通或防火墙限制。"])
            actions.extend([
                "用路由跟踪定位不通位置，并确认目标主机是否在线。",
                "确认 ICMP 是否被策略禁用；不能只凭 Ping 判断服务不可用。",
            ])
        slow = [r for r in results if r.get("avg_ms") is not None and float(r["avg_ms"]) >= 100]
        if slow:
            risks.append(f"{len(slow)} 个目标平均延迟不低于 100ms，可能存在链路拥塞或跨运营商路径。")
            actions.append("对延迟最高的目标分段时间抓包，并检查链路利用率与路由路径。")
        if statuses.get("reachable"):
            actions.append("结合 HTTP 和 TCP 探测确认 ICMP 可达的服务是否真的可用。")
    elif probe_type == "http":
        if statuses.get("server_error"):
            risks.append("存在 HTTP 5xx 响应，服务端或上游依赖可能异常。")
            actions.append("检查服务日志、网关日志和上游依赖健康状态。")
        if statuses.get("client_error"):
            risks.append("存在 HTTP 4xx 响应，可能是鉴权、路径或 WAF 拦截问题。")
            actions.append("核对请求方法、URL、Headers、认证信息和访问控制规则。")
        if statuses.get("tls_error"):
            risks.append("存在 TLS 校验失败，证书链、有效期、信任库或中间设备可能异常。")
            actions.append("检查证书有效期、SAN、证书链和客户端信任库。")
        if statuses.get("timeout") or statuses.get("unreachable"):
            risks.append("部分 HTTP 请求无法建立连接，可能目标离线或端口被过滤。")
            actions.append("用 Ping/TCP 探测确认基础连通性和 80/443 端口状态。")
        actions.extend([
            "确认最终 URL 和重定向策略是否符合业务预期。",
            "检查慢请求的服务端耗时、网络耗时和资源大小。",
        ])
    elif probe_type == "tcp":
        if statuses.get("open"):
            risks.append("存在对外开放端口，需确认是否都是授权服务暴露面。")
            actions.append("对照资产基线核对开放端口，关闭未使用服务并限制来源访问。")
        if statuses.get("closed"):
            actions.append("端口被拒绝通常说明主机可达但服务未监听，核对服务进程和监听地址。")
        if statuses.get("timeout"):
            risks.append("部分端口连接超时，中间设备可能静默丢弃 SYN。")
            actions.append("在客户端与目标端同时抓包，确认防火墙是否仅丢弃而不回 RST。")
        if statuses.get("unreachable") or statuses.get("error"):
            actions.append("检查路由、DNS 解析和目标主机状态。")
    return risks, actions


def build_probe_report(probe_type: str, summary: dict, results: list[dict]) -> str:
    summary = summary or {}
    statuses = {str(k): int(v) for k, v in (summary.get("statuses") or {}).items()}
    if not statuses and results:
        for result in results:
            status = _probe_status(result)
            statuses[status] = statuses.get(status, 0) + 1
    ok_statuses = {"reachable", "ok", "redirect", "open"}
    ok_count = sum(count for status, count in statuses.items() if status in ok_statuses)
    error_count = sum(count for status, count in statuses.items() if status not in ok_statuses)
    merged_summary = {**summary, "statuses": statuses, "ok_count": ok_count, "error_count": error_count}
    bad = [r for r in results if r.get("ok") is False or _probe_status(r) not in ok_statuses]
    good = [r for r in results if r not in bad]

    lines = [
        "# NOCSlate 网络探测离线报告",
        "",
        "> 本报告由本地探测结果生成，不依赖网络和 AI API。",
        "",
        "## 结论",
        "",
        _probe_conclusion(probe_type, merged_summary, results),
        "",
        "## 探测概览",
        "",
        "| 项目 | 值 |",
        "|---|---|",
        f"| 探测类型 | {probe_type.upper()} |",
        f"| 结果数 | {len(results)} |",
        f"| 正常 | {ok_count} |",
        f"| 异常 | {error_count} |",
        f"| 耗时 | {merged_summary.get('duration_ms', '-')} ms |",
        "",
        "## 状态分布",
        "",
    ]
    if statuses:
        lines.extend([
            "| 状态 | 数量 |",
            "|---|---|",
        ])
        for status, count in sorted(statuses.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"| {_cell(PROBE_STATUS_LABELS.get(status, status))} | {count} |")
    else:
        lines.append("无结果。")

    if bad:
        lines.extend(["", "## 异常结果", "", _probe_result_table(bad[:30], probe_type)])
        if len(bad) > 30:
            lines.append(f"\n> 仅展示前 30 条异常，共 {len(bad)} 条。")
    if good:
        lines.extend(["", "## 正常结果示例", "", _probe_result_table(good[:10], probe_type)])

    risks, actions = _probe_risk_and_actions(probe_type, merged_summary, results)
    if not risks:
        risks = ["未发现明显的目标离线、服务错误或 TLS 异常模式。"]
    if not actions:
        actions = ["保持监控；如有业务异常，结合服务日志和更完整的抓包继续核对。"]
    lines.extend(["", "## 可能原因与风险", ""])
    lines.extend(f"- {risk}" for risk in risks)
    lines.extend(["", "## 排查建议", ""])
    lines.extend(f"- {action}" for action in actions)
    lines.extend([
        "",
        "## 局限性",
        "",
        "Ping 只能反映 ICMP 可达性；端口扫描只反映 TCP 握手是否完成；",
        "HTTP 检查只记录状态和耗时，不保存响应正文。探测结果不能替代安全评估。",
    ])
    return "\n".join(lines) + "\n"


def build_exposure_report(summary: dict, assets: list[dict], findings: list[dict]) -> str:
    summary = summary or {}
    risk_counts = {str(k): int(v) for k, v in (summary.get("risk_counts") or {}).items()}
    lines = [
        "# 暴露面与资产发现离线报告",
        "",
        "> 本报告由本地扫描结果生成，不依赖网络和 AI API。仅用于你有权测试的网络。",
        "",
        "## 结论",
        "",
    ]
    if findings:
        high = risk_counts.get("critical", 0) + risk_counts.get("high", 0)
        lines.append(
            f"本次发现 {len(assets)} 条资产记录、{int(summary.get('open_count', 0))} 个开放端口，"
            f"归并出 {len(findings)} 项风险发现，其中高优先级 {high} 项。"
        )
    else:
        lines.append("在授权端口范围内未发现命中的暴露面风险规则。")
    lines.extend([
        "",
        "## 概览",
        "",
        "| 项目 | 值 |",
        "|---|---|",
        f"| 目标数 | {summary.get('targets_total', len(assets))} |",
        f"| 存活主机 | {summary.get('hosts_alive', 0)} |",
        f"| 检查端点 | {summary.get('endpoint_total', 0)} |",
        f"| 开放端口 | {summary.get('open_count', 0)} |",
        f"| 风险发现 | {len(findings)} |",
        f"| 耗时 | {summary.get('duration_ms', '-')} ms |",
        "",
        "## 资产与端口",
        "",
        "| 目标 | 状态 | 开放端口 | 说明 |",
        "|---|---|---|---|",
    ])
    for asset in assets[:50]:
        lines.append(
            "| {} | {} | {} | {} |".format(
                _cell(asset.get("target", "")),
                _cell(asset.get("status", "")),
                _cell(", ".join(str(p) for p in asset.get("open_ports", [])) or "-"),
                _cell(asset.get("detail", "")),
            )
        )
    if len(assets) > 50:
        lines.append(f"\n> 仅展示前 50 条资产记录，共 {len(assets)} 条。")

    lines.extend(["", "## 风险发现", ""])
    if not findings:
        lines.append("未命中内置风险规则。")
    for index, finding in enumerate(findings[:50], 1):
        lines.extend([
            f"### {index}. {finding.get('title', '风险发现')}",
            "",
            f"- 级别：{finding.get('severity', '-')}",
            f"- 证据：{finding.get('evidence', '-')}",
            f"- 建议：{finding.get('advice', '-')}",
            "",
        ])
    if len(findings) > 50:
        lines.append(f"> 仅展示前 50 条风险发现，共 {len(findings)} 条。")

    lines.extend([
        "## 局限性",
        "",
        "- TCP connect 扫描只能判断握手是否完成，不能证明服务版本完整。",
        "- 服务识别基于常见端口、Banner、HTTP 响应头和 TLS 证书，不能替代专业安全评估。",
        "- 未扫描的端口、UDP 服务和需要认证的业务风险不会被列出。",
    ])
    return "\n".join(lines) + "\n"
