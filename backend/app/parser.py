from __future__ import annotations

from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS
from scapy.utils import PcapReader

DEFAULT_MAX_PACKETS = 50_000
PAYLOAD_PREVIEW_BYTES = 96

TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

ICMP_TYPES = {
    0: "Echo 应答",
    3: "目标不可达",
    8: "Echo 请求",
    11: "超时",
}

ICMP_CODE_3 = {
    0: "网络不可达",
    1: "主机不可达",
    2: "协议不可达",
    3: "端口不可达",
    4: "需要分片",
    13: "管理禁止",
}

ICMP_CODE_11 = {
    0: "TTL 传输中超时",
    1: "分片重组超时",
}

TLS_HANDSHAKE_TYPES = {
    0: "HelloRequest",
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
}

TLS_ALERT_LEVELS = {1: "warning", 2: "fatal"}

TLS_ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    90: "user_canceled",
    100: "no_renegotiation",
    112: "unrecognized_name",
    116: "certificate_required",
}

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"TRACE ",
    b"CONNECT ",
)


def flags_string(value: int) -> str:
    out = []
    for letter, bit in (("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08),
                        ("A", 0x10), ("U", 0x20), ("E", 0x40), ("C", 0x80)):
        if value & bit:
            out.append(letter)
    return "".join(out)


def flags_meaning(flags: str) -> str:
    return "+".join(TCP_FLAG_NAMES.get(ch, ch) for ch in flags)


def _flow_key(src: str, sport: Any, dst: str, dport: Any, proto: str) -> tuple[str, str]:
    a = (src, sport if sport is not None else -1)
    b = (dst, dport if dport is not None else -1)
    first, second = (a, b) if a <= b else (b, a)
    key = f"{first[0]}:{first[1]}<->{second[0]}:{second[1]}/{proto}"
    direction = "fwd" if a <= b else "rev"
    return key, direction


def _dns_info(dns_bytes: bytes, dns_layer) -> dict | None:
    if len(dns_bytes) < 4:
        return None
    qr = (dns_bytes[2] >> 7) & 1
    rcode = dns_bytes[3] & 0x0F
    qname = ""
    try:
        qd = dns_layer.qd
        if qd is not None and hasattr(qd, "__len__") and not isinstance(qd, (bytes, str)):
            qd = qd[0] if len(qd) else None
        if qd is not None:
            qname = bytes(qd.qname).decode("utf-8", "replace").rstrip(".")
    except Exception:
        qname = ""
    return {
        "qr": bool(qr),
        "rcode": rcode,
        "rcode_name": DNS_RCODES.get(rcode, f"rcode-{rcode}"),
        "qname": qname,
    }


def _http_info(raw: bytes) -> dict | None:
    head = raw[:512]
    if head.startswith(b"HTTP/1.") and len(head) >= 12:
        try:
            code = int(head[9:12])
        except ValueError:
            return None
        end = head.find(b"\r")
        reason = head[13:end].decode("utf-8", "replace") if end > 13 else ""
        return {"type": "response", "code": code, "reason": reason}
    first_line = head.split(b"\r", 1)[0]
    for method in HTTP_METHODS:
        if first_line.startswith(method):
            parts = first_line.decode("utf-8", "replace").split(" ")
            if len(parts) >= 2:
                return {"type": "request", "method": parts[0], "path": parts[1]}
            return None
    return None


def _tls_info(raw: bytes) -> dict | None:
    if len(raw) < 6 or raw[0] not in (20, 21, 22, 23):
        return None
    if raw[1] != 0x03 or raw[2] > 0x04:
        return None
    content_type = raw[0]
    if content_type == 21:
        if len(raw) < 7:
            return None
        level, desc = raw[5], raw[6]
        return {
            "kind": "alert",
            "level": TLS_ALERT_LEVELS.get(level, f"level-{level}"),
            "description": TLS_ALERT_DESCRIPTIONS.get(desc, f"alert-{desc}"),
            "code": desc,
        }
    if content_type == 22:
        hs = raw[5]
        name = TLS_HANDSHAKE_TYPES.get(hs, f"handshake-{hs}")
        return {"kind": "handshake", "name": name, "code": hs}
    if content_type == 23:
        return {"kind": "application_data", "name": "ApplicationData", "code": 23}
    return None


def _info_for(rec: dict) -> str:
    proto = rec["proto"]
    if proto == "TCP":
        base = f"{rec['sport']} -> {rec['dport']} [{rec['flags_meaning']}] Seq={rec['seq']} Win={rec['window']} Len={rec['payload_len']}"
        if rec["dns"]:
            d = rec["dns"]
            if d["qr"]:
                base = f"{rec['sport']} -> {rec['dport']} DNS 响应 {d['rcode_name']} ({d['rcode']})"
            else:
                base = f"{rec['sport']} -> {rec['dport']} DNS 查询 {d['qname']}"
        elif rec["tls"]:
            t = rec["tls"]
            if t["kind"] == "alert":
                base = f"{rec['sport']} -> {rec['dport']} TLS Alert [{t['level']}] {t['description']}"
            else:
                base = f"{rec['sport']} -> {rec['dport']} TLS {t.get('name', t['kind'])}"
        elif rec["http"]:
            h = rec["http"]
            if h["type"] == "response":
                base = f"{rec['sport']} -> {rec['dport']} HTTP/1.1 {h['code']} {h['reason']}".rstrip()
            else:
                base = f"{rec['sport']} -> {rec['dport']} {h['method']} {h['path']}"
        return base
    if proto == "UDP":
        return f"{rec['sport']} -> {rec['dport']} Len={rec['payload_len']}"
    if proto == "ICMP":
        icmp = rec["icmp"]
        text = f"ICMP {icmp['name']}"
        if icmp["type"] == 3 and icmp["code"] in ICMP_CODE_3:
            text += f" ({ICMP_CODE_3[icmp['code']]})"
        elif icmp["type"] == 11 and icmp["code"] in ICMP_CODE_11:
            text += f" ({ICMP_CODE_11[icmp['code']]})"
        return text
    if proto == "ARP":
        return rec["arp"]["info"]
    return f"{proto} {rec['frame_len']} 字节"


def parse_record(no: int, ts: float, pkt) -> dict:
    rec: dict[str, Any] = {
        "no": no,
        "ts": ts,
        "src": "",
        "dst": "",
        "src_mac": "",
        "dst_mac": "",
        "proto": "其他",
        "sport": None,
        "dport": None,
        "tcp_flags": None,
        "flags_meaning": None,
        "seq": None,
        "ack": None,
        "window": None,
        "payload_len": 0,
        "payload_preview": "",
        "dns": None,
        "http": None,
        "tls": None,
        "icmp": None,
        "arp": None,
        "flow": "",
        "flow_dir": "",
        "frame_len": len(pkt),
    }

    eth = pkt.getlayer(Ether)
    if eth is not None:
        rec["src_mac"] = eth.src
        rec["dst_mac"] = eth.dst

    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    tcp = pkt.getlayer(TCP)
    udp = pkt.getlayer(UDP)
    icmp = pkt.getlayer(ICMP)
    arp = pkt.getlayer(ARP)

    if ip_layer is not None:
        rec["src"] = ip_layer.src
        rec["dst"] = ip_layer.dst

    if arp is not None:
        rec["proto"] = "ARP"
        op = int(arp.op)
        if op == 1:
            info = f"谁有 {arp.pdst}？告诉 {arp.psrc}"
        elif op == 2:
            info = f"{arp.psrc} 位于 {arp.hwsrc}"
        else:
            info = f"ARP op={op}"
        rec["arp"] = {"op": op, "info": info}
        rec["flow"], rec["flow_dir"] = _flow_key(rec["src"], None, rec["dst"], None, "ARP")
    elif tcp is not None:
        rec["proto"] = "TCP"
        rec["sport"] = int(tcp.sport)
        rec["dport"] = int(tcp.dport)
        raw_flags = int(tcp.flags)
        rec["tcp_flags"] = flags_string(raw_flags)
        rec["flags_meaning"] = flags_meaning(rec["tcp_flags"])
        rec["seq"] = int(tcp.seq)
        rec["ack"] = int(tcp.ack)
        rec["window"] = int(tcp.window)
        payload = bytes(tcp.payload)
        rec["payload_len"] = len(payload)
        preview = payload[:PAYLOAD_PREVIEW_BYTES]
        rec["payload_preview"] = preview.hex()
        if rec["sport"] == 53 or rec["dport"] == 53:
            if len(payload) > 2:
                try:
                    dns_layer = DNS(payload[2:])
                    rec["dns"] = _dns_info(bytes(dns_layer), dns_layer)
                except Exception:
                    rec["dns"] = None
        if rec["dns"] is None:
            rec["tls"] = _tls_info(payload)
        if rec["dns"] is None and rec["tls"] is None:
            rec["http"] = _http_info(payload)
        rec["flow"], rec["flow_dir"] = _flow_key(rec["src"], rec["sport"], rec["dst"], rec["dport"], "TCP")
    elif udp is not None:
        rec["proto"] = "UDP"
        rec["sport"] = int(udp.sport)
        rec["dport"] = int(udp.dport)
        payload = bytes(udp.payload)
        rec["payload_len"] = len(payload)
        rec["payload_preview"] = payload[:PAYLOAD_PREVIEW_BYTES].hex()
        if rec["sport"] == 53 or rec["dport"] == 53:
            dns_layer = pkt.getlayer(DNS)
            if dns_layer is not None:
                rec["dns"] = _dns_info(bytes(dns_layer), dns_layer)
        rec["flow"], rec["flow_dir"] = _flow_key(rec["src"], rec["sport"], rec["dst"], rec["dport"], "UDP")
    elif icmp is not None:
        rec["proto"] = "ICMP"
        itype = int(icmp.type)
        icode = int(icmp.code)
        rec["icmp"] = {
            "type": itype,
            "code": icode,
            "name": ICMP_TYPES.get(itype, f"type-{itype}"),
        }
        rec["flow"], rec["flow_dir"] = _flow_key(rec["src"], None, rec["dst"], None, "ICMP")

    rec["info"] = _info_for(rec)
    return rec


def parse_pcap(path: str, max_packets: int = DEFAULT_MAX_PACKETS) -> tuple[list[dict], bool]:
    records: list[dict] = []
    capped = False
    with PcapReader(path) as reader:
        for no, pkt in enumerate(reader, start=1):
            if no > max_packets:
                capped = True
                break
            try:
                records.append(parse_record(no, float(pkt.time), pkt))
            except Exception:
                continue
    return records, capped
