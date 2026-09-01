from __future__ import annotations

import re
from collections import Counter
from pathlib import PureWindowsPath


MAX_CONFIG_BYTES = 20 * 1024 * 1024
MAX_EVIDENCE_LINES = 6

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
}

VENDOR_PATTERNS = [
    ("H3C", r"\bdisplay current-configuration\b|\bport trunk permit vlan\b|^\s*sysname .*H3C|\binfo-center loghost\b", re.I),
    ("Huawei", r"\bdisplay current-configuration\b|\bvlan batch\b|\bntp-service\b|\bsnmp-agent\b|\bport trunk allow-pass vlan\b", re.I),
    ("Ruijie", r"\bRGOS\b|\bRuijie\b|\benable secret\b|\bline vty\b|\bsnmp-server community\b", re.I),
    ("ZTE", r"\bZXR10\b|\bset router-name\b|\bcreate user\b|\bset ip service telnet\b", re.I),
]

NAME_PATTERNS = [
    r"^\s*(?:display\s+)?sysname\s+(\S+)",
    r"^\s*set\s+router-name\s+(\S+)",
    r"^\s*hostname\s+(\S+)",
    r"^\s*router-name\s+(\S+)",
]

SECRET_PATTERN = re.compile(
    r"(?i)\b((?:password|passwd|secret|community|psk|key|pre-shared-key)\b(?:\s+\S+){0,2})"
)


class ConfigAuditError(ValueError):
    pass


def decode_config(data: bytes, max_bytes: int = MAX_CONFIG_BYTES) -> str:
    if not data:
        raise ConfigAuditError("文件为空")
    if len(data) > max_bytes:
        raise ConfigAuditError("文件过大（上限 20MB）")
    if b"\x00" in data[:4096]:
        raise ConfigAuditError("文件疑似二进制内容，请上传文本格式的配置或日志")
    for encoding in ("utf-8-sig", "gb18030"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _lines(text: str) -> list[str]:
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def detect_vendor(text: str) -> str:
    scores = Counter()
    for vendor, pattern, flags in VENDOR_PATTERNS:
        matches = len(re.findall(pattern, text, flags))
        if matches:
            scores[vendor] = matches
    if not scores:
        return "Unknown"
    top = scores.most_common()
    if len(top) > 1 and top[0][1] == top[1][1]:
        if "Huawei" in scores and "H3C" in scores:
            return "Huawei" if re.search(r"\bvlan batch\b|\bntp-service\b", text, re.I) else "H3C"
    return top[0][0]


def detect_device_name(text: str) -> str:
    for pattern in NAME_PATTERNS:
        match = re.search(pattern, text, re.I | re.M)
        if match:
            return match.group(1).strip("\"'")[:64]
    return "未识别"


def redact_config_line(line: str) -> str:
    def replace(match: re.Match) -> str:
        value = match.group(1)
        parts = value.split()
        if len(parts) < 2:
            return "***"
        return " ".join(parts[:-1]) + " ***"

    return SECRET_PATTERN.sub(replace, line)


def _excerpt(text: str, limit: int = MAX_EVIDENCE_LINES) -> str:
    rows = _lines(text)[:limit]
    return "\n".join(redact_config_line(row) for row in rows)


def _finding(
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    evidence: str,
    advice: str,
) -> dict:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "category": category,
        "evidence": _excerpt(evidence),
        "advice": advice,
    }


def _regex_evidence(lines: list[str], pattern: str, flags: int = re.I) -> str:
    matched = [line for line in lines if re.search(pattern, line, flags)]
    return "\n".join(matched)


def audit_config(text: str, vendor: str | None = None) -> dict:
    rows = _lines(text)
    nonblank = [row for row in rows if row.strip()]
    vendor = vendor or detect_vendor(text)
    findings: list[dict] = []

    telnet = _regex_evidence(rows, r"\btelnet\b|\bset ip service telnet\b|\bline vty\b")
    if telnet:
        findings.append(_finding(
            "telnet-enabled", "Telnet 明文管理面", "high", "管理协议", telnet,
            "关闭 Telnet，改用 SSHv2；VTY/line 下仅允许 SSH，并绑定管理 ACL。",
        ))

    ftp_tftp = _regex_evidence(rows, r"\b(ftp|tftp)\b.*\bserver\b|\bftp server enable\b|\btftp-server\b|\bset ftp server enable\b")
    if ftp_tftp:
        findings.append(_finding(
            "ftp-tftp-enabled", "FTP/TFTP 明文文件服务", "high", "文件传输", ftp_tftp,
            "停用 FTP/TFTP，改用 SFTP/SCP，并限制源地址与临时开启时间。",
        ))

    snmp = _regex_evidence(rows, r"\bsnmp-agent\b|\bsnmp-server community\b")
    if snmp:
        findings.append(_finding(
            "snmp-enabled", "SNMP 服务已启用", "low", "管理协议", snmp,
            "确认必须启用的监控主机，限制 community 使用范围，优先升级 SNMPv3。",
        ))
    weak_snmp = _regex_evidence(rows, r"(?:snmp(?:-server)?\s+community\s+(?:index\s+)?)(public|private)\b|\bsnmp-agent\s+community\s+(?:read|write)\s+(public|private)\b")
    if weak_snmp:
        findings.append(_finding(
            "snmp-default-community", "SNMP 默认 community", "critical", "凭据", weak_snmp,
            "立即修改默认 community；如设备支持，使用 SNMPv3 认证和加密。",
        ))
    v1v2 = _regex_evidence(rows, r"snmp-agent\s+sys-info\s+version\s+.*(v1|v2c)|snmp-server\s+community|snmp-agent\s+community")
    if v1v2:
        findings.append(_finding(
            "snmp-v1-v2c", "SNMP v1/v2c 弱协议", "medium", "管理协议", v1v2,
            "迁移到 SNMPv3，禁用 v1/v2c，并配置视图和源地址 ACL。",
        ))

    plaintext = _regex_evidence(
        rows,
        r"password\s+simple\b|password\s+0\b|enable\s+password\b|set\s+.*password\s+(?:0|simple)\b",
    )
    if plaintext:
        findings.append(_finding(
            "plaintext-password", "明文或可逆密码配置", "critical", "凭据", plaintext,
            "使用设备推荐的 cipher/加密方式重新配置账号，并检查历史配置是否泄露。",
        ))

    http = _regex_evidence(rows, r"\bip http enable\b|\bhttp server enable\b|\bset web server enable\b|\bstelnet server enable\b")
    if http and re.search(r"http|web", http, re.I):
        findings.append(_finding(
            "plaintext-management", "HTTP/Web 明文管理", "high", "管理协议", http,
            "关闭 HTTP/Web 管理或强制跳转 HTTPS，并只绑定管理 VLAN/ACL。",
        ))

    vty = _regex_evidence(rows, r"\bline vty\b|\buser-interface vty\b|\bset vty\b")
    has_vty_acl = re.search(
        r"access-class|acl\s+\d+.*inbound|telnet\s+.*acl|ssh\s+.*acl|filter\s+.*acl",
        text, re.I,
    )
    if vty and not has_vty_acl:
        findings.append(_finding(
            "vty-no-acl", "VTY 管理入口缺少 ACL", "high", "访问控制", vty,
            "为 VTY 配置管理源地址 ACL，只允许堡垒机或指定网段登录。",
        ))

    has_ssh = re.search(r"\bssh\b|\bstelnet\b", text, re.I)
    if not has_ssh and (telnet or vty):
        findings.append(_finding(
            "ssh-not-found", "未发现 SSH 配置", "high", "管理协议", telnet or vty,
            "生成并启用 RSA/ECDSA 密钥，配置 SSHv2 后关闭 Telnet。",
        ))

    loghost = re.search(r"logging\s+host|info-center\s+loghost|set\s+logging\s+(?:server|host)|logging\s+server", text, re.I)
    if not loghost:
        findings.append(_finding(
            "no-log-host", "未发现集中日志服务器", "medium", "审计", text,
            "配置集中 Syslog 服务器，保留时间同步、登录、变更和关键操作日志。",
        ))

    ntp = re.search(r"ntp\s+server|ntp-service|sntp|set\s+ntp", text, re.I)
    if not ntp:
        findings.append(_finding(
            "no-ntp", "未发现 NTP 时间同步", "medium", "审计", text,
            "配置至少两个内部 NTP 源，确保日志时间可用于关联分析。",
        ))

    vlan1 = _regex_evidence(
        rows,
        r"port\s+(?:trunk\s+)?(?:permit|allow-pass)\s+vlan\s+(?:all|1)\b|vlan\s+1\b|switchport\s+access\s+vlan\s+1\b",
    )
    if vlan1:
        findings.append(_finding(
            "vlan1-use", "VLAN 1 或 Trunk 全放行风险", "medium", "二层安全", vlan1,
            "业务口移出 VLAN 1；Trunk 明确放行所需 VLAN，并设置 PVID。",
        ))

    stp_disabled = re.search(r"(?:undo|no)\s+(?:stp|spanning-tree)\s+(?:enable|global)|set\s+stp\s+disable", text, re.I)
    if stp_disabled:
        findings.append(_finding(
            "stp-disabled", "STP 被禁用", "medium", "二层安全", stp_disabled,
            "如确认无环且必须禁用，记录变更；否则启用 STP/RSTP/MSTP 并配置根桥保护。",
        ))

    findings.sort(key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["id"]))
    summary = dict(Counter(item["severity"] for item in findings))
    return {
        "vendor": vendor,
        "device_name": detect_device_name(text),
        "config_line_count": len(nonblank),
        "finding_count": len(findings),
        "summary": summary,
        "findings": findings,
    }


def audit_upload(filename: str, data: bytes) -> dict:
    safe_name = PureWindowsPath(filename or "config.txt").name
    text = decode_config(data)
    result = audit_config(text)
    report = build_report(safe_name, result)
    return {
        "filename": safe_name,
        **result,
        "report": report,
    }


def build_exposure_context(result: dict) -> str:
    context = {
        "vendor": result.get("vendor"),
        "device_name": result.get("device_name"),
        "config_line_count": result.get("config_line_count"),
        "summary": result.get("summary"),
        "findings": result.get("findings", [])[:50],
    }
    return context


def build_report(filename: str, result: dict) -> str:
    summary = result.get("summary", {})
    total = result.get("finding_count", len(result.get("findings", [])))
    lines = [
        "# 网络设备配置审计报告",
        "",
        "## 文件概览",
        "",
        f"- 文件：{filename}",
        f"- 识别厂商：{result.get('vendor', 'Unknown')}",
        f"- 设备名称：{result.get('device_name', '未识别')}",
        f"- 有效配置行：{result.get('config_line_count', 0)}",
        f"- 审计发现：{total} 项",
        "",
        "## 风险分布",
        "",
    ]
    if summary:
        for severity in ("critical", "high", "medium", "low"):
            if summary.get(severity):
                lines.append(f"- {SEVERITY_LABEL[severity]}：{summary[severity]}")
    else:
        lines.append("- 未命中内置审计规则。")

    lines.extend(["", "## 详细发现", ""])
    for index, finding in enumerate(result.get("findings", []), 1):
        lines.extend([
            f"### {index}. {finding['title']}",
            "",
            f"- 级别：{SEVERITY_LABEL.get(finding['severity'], finding['severity'])}",
            f"- 类别：{finding['category']}",
            "",
            "**证据（已脱敏）**",
            "",
            "```text",
            finding.get("evidence") or "(未展示证据)",
            "```",
            "",
            "**加固建议**",
            "",
            finding.get("advice", ""),
            "",
        ])

    lines.extend([
        "## 局限性",
        "",
        "- 本报告基于常见命令特征做静态检查，不执行设备，也不保证覆盖所有厂商版本。",
        "- 缺少某项发现不等于配置绝对安全，建议结合资产边界、账号台账和变更记录复核。",
        "- 证据中的凭据类字段已脱敏；请勿上传未脱敏配置到不受信任的第三方服务。",
        "",
        "## 加固路线",
        "",
        "1. 先处理默认 community、明文密码和高危明文管理协议。",
        "2. 限制 VTY/Web/SNMP 来源，统一使用 SSHv2 和 SNMPv3。",
        "3. 配置集中日志、NTP 和配置备份，形成持续审计基线。",
    ])
    return "\n".join(lines)
