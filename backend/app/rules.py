from __future__ import annotations

from collections import defaultdict

RULES = [
    {"id": "rst", "name": "TCP RST", "severity": "error",
     "description": "出现 RST 报文，连接被拒绝或被强制重置"},
    {"id": "retransmission", "name": "TCP 重传", "severity": "warning",
     "description": "同一流相同序号的数据段重复出现，通常意味着丢包"},
    {"id": "zero_window", "name": "TCP 零窗口", "severity": "warning",
     "description": "服务端通告接收窗口为 0，接收方处理不过来"},
    {"id": "syn_halfopen", "name": "SYN 半开", "severity": "warning",
     "description": "同一流多次 SYN 未收到 SYN-ACK，服务不可达或被过滤"},
    {"id": "syn_scan", "name": "疑似端口扫描", "severity": "error",
     "description": "同一源地址向大量不同端口发送 SYN 且未建立连接"},
    {"id": "dns_fail", "name": "DNS 解析失败", "severity": "warning",
     "description": "DNS 响应 rcode 非 0（如 NXDOMAIN、SERVFAIL）"},
    {"id": "http_error", "name": "HTTP 错误响应", "severity": "warning",
     "description": "HTTP 状态码 >= 400"},
    {"id": "tls_alert", "name": "TLS 告警", "severity": "error",
     "description": "出现 TLS alert 记录（如 handshake_failure）"},
    {"id": "icmp_err", "name": "ICMP 错误", "severity": "warning",
     "description": "ICMP 目标不可达（type 3）或超时（type 11）"},
]

SEVERITY_BY_RULE = {r["id"]: r["severity"] for r in RULES}
RULE_NAME_BY_ID = {r["id"]: r["name"] for r in RULES}

SCAN_PORT_THRESHOLD = 15


def _hit(rule_id: str, verdict: str, detail: str) -> dict:
    return {
        "rule": rule_id,
        "name": RULE_NAME_BY_ID[rule_id],
        "severity": SEVERITY_BY_RULE[rule_id],
        "verdict": verdict,
        "detail": detail,
    }


def run_rules(packets: list[dict]) -> dict:
    packet_hits: dict[int, list[dict]] = defaultdict(list)

    seen_segments: dict[tuple, int] = {}
    flows: dict[str, dict] = {}
    scan_ports: dict[str, set] = defaultdict(set)
    scan_syn_nos: dict[str, list[int]] = defaultdict(list)
    scan_established: set[str] = set()

    for p in packets:
        if p["proto"] != "TCP":
            if p["proto"] == "UDP" and p["dns"] and p["dns"]["qr"] and p["dns"]["rcode"] != 0:
                packet_hits[p["no"]].append(_hit(
                    "dns_fail",
                    f"DNS 解析失败：{p['dns']['rcode_name']}",
                    f"查询 {p['dns']['qname'] or '(未知域名)'} 返回 rcode={p['dns']['rcode']}",
                ))
            if p["proto"] == "ICMP" and p["icmp"] and p["icmp"]["type"] in (3, 11):
                name = "目标不可达" if p["icmp"]["type"] == 3 else "超时"
                packet_hits[p["no"]].append(_hit(
                    "icmp_err",
                    f"ICMP {name}",
                    f"{p['src']} -> {p['dst']} type={p['icmp']['type']} code={p['icmp']['code']}",
                ))
            continue

        fkey = p["flow"]
        fl = flows.setdefault(fkey, {
            "flow": fkey, "packets": 0, "syn": 0, "synack": 0,
            "rst": 0, "rst_ack": 0, "fin": 0, "syn_nos": [], "rst_nos": [],
            "server_port": None,
        })
        fl["packets"] += 1

        flags = p["tcp_flags"] or ""
        is_syn = "S" in flags and "A" not in flags
        is_synack = "S" in flags and "A" in flags
        is_rst = "R" in flags
        is_fin = "F" in flags

        if is_syn:
            fl["syn"] += 1
            fl["syn_nos"].append(p["no"])
            if fl["server_port"] is None:
                fl["server_port"] = p["dport"]
            scan_ports[p["src"]].add(p["dport"])
            scan_syn_nos[p["src"]].append(p["no"])
        if is_synack:
            fl["synack"] += 1
            scan_established.add(p["dst"])
        if is_rst:
            fl["rst"] += 1
            fl["rst_nos"].append(p["no"])
            if "A" in flags:
                fl["rst_ack"] += 1
            kind = "RST+ACK" if "A" in flags else "RST"
            packet_hits[p["no"]].append(_hit(
                "rst",
                f"{kind}：连接被{'拒绝' if fl['syn'] and fl['synack'] == 0 else '重置'}",
                f"{p['src']}:{p['sport']} -> {p['dst']}:{p['dport']} 发送 {kind}，流 {fkey}",
            ))
        if is_fin:
            fl["fin"] += 1

        # 重传：同方向同 seq/len 的数据段（或 SYN/FIN）重复出现
        if p["seq"] is not None and (p["payload_len"] > 0 or is_syn or is_fin):
            seg_key = (p["src"], p["sport"], p["dst"], p["dport"], p["seq"], p["payload_len"])
            if seg_key in seen_segments:
                first_no = seen_segments[seg_key]
                packet_hits[p["no"]].append(_hit(
                    "retransmission",
                    "TCP 重传",
                    f"seq={p['seq']} len={p['payload_len']} 与 #{first_no} 重复，疑似丢包",
                ))
            else:
                seen_segments[seg_key] = p["no"]

        # 零窗口：以同流首个 SYN 的目的端口确定服务端方向
        if (p["window"] == 0 and "S" not in flags and "R" not in flags
                and fl["server_port"] is not None and p["sport"] == fl["server_port"]):
            packet_hits[p["no"]].append(_hit(
                "zero_window",
                "零窗口：接收方处理不过来",
                f"服务端 {p['src']}:{p['sport']} 通告 window=0，发送方需暂停",
            ))

        if p["dns"] and p["dns"]["qr"] and p["dns"]["rcode"] != 0:
            packet_hits[p["no"]].append(_hit(
                "dns_fail",
                f"DNS 解析失败：{p['dns']['rcode_name']}",
                f"查询 {p['dns']['qname'] or '(未知域名)'} 返回 rcode={p['dns']['rcode']}",
            ))
        if p["http"] and p["http"]["type"] == "response" and p["http"]["code"] >= 400:
            packet_hits[p["no"]].append(_hit(
                "http_error",
                f"HTTP {p['http']['code']} {p['http']['reason']}".rstrip(),
                f"{p['src']}:{p['sport']} 返回错误状态码",
            ))
        if p["tls"] and p["tls"]["kind"] == "alert":
            packet_hits[p["no"]].append(_hit(
                "tls_alert",
                f"TLS Alert [{p['tls']['level']}] {p['tls']['description']}",
                f"{p['src']}:{p['sport']} -> {p['dst']}:{p['dport']} 发送 TLS 告警",
            ))
        if p["icmp"] and p["icmp"]["type"] in (3, 11):
            name = "目标不可达" if p["icmp"]["type"] == 3 else "超时"
            packet_hits[p["no"]].append(_hit(
                "icmp_err",
                f"ICMP {name}",
                f"{p['src']} -> {p['dst']} type={p['icmp']['type']} code={p['icmp']['code']}",
            ))

    # 流级：SYN 半开
    for fl in flows.values():
        if fl["syn"] >= 2 and fl["synack"] == 0 and fl["rst"] == 0:
            for no in fl["syn_nos"]:
                packet_hits[no].append(_hit(
                    "syn_halfopen",
                    "多次 SYN 无响应：服务不可达或被过滤",
                    f"流 {fl['flow']} 共发送 {fl['syn']} 个 SYN，未收到 SYN-ACK",
                ))

    # 源级：端口扫描
    for src, ports in scan_ports.items():
        if len(ports) >= SCAN_PORT_THRESHOLD and src not in scan_established:
            for no in scan_syn_nos[src][:20]:
                packet_hits[no].append(_hit(
                    "syn_scan",
                    "疑似端口扫描",
                    f"{src} 向 {len(ports)} 个不同端口发送 SYN 且未建立任何连接",
                ))

    flow_stats = sorted(flows.values(), key=lambda f: (-f["packets"], f["flow"]))
    for fl in flow_stats:
        fl.pop("syn_nos", None)
        fl.pop("rst_nos", None)

    summary = defaultdict(int)
    for hits in packet_hits.values():
        for h in hits:
            summary[h["rule"]] += 1

    return {
        "packet_hits": dict(packet_hits),
        "flow_stats": flow_stats[:100],
        "rule_summary": dict(summary),
    }
