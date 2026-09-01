from app import parser
from app.rules import run_rules


def tcp_pkt(no, src="10.0.0.1", sport=12345, dst="10.0.0.2", dport=80,
            flags="", seq=None, window=8192, payload_len=0,
            dns=None, http=None, tls=None, icmp=None, proto="TCP"):
    p = {
        "no": no, "ts": float(no), "src": src, "dst": dst,
        "src_mac": "", "dst_mac": "", "proto": proto,
        "sport": sport, "dport": dport,
        "tcp_flags": flags, "flags_meaning": None,
        "seq": seq, "ack": None, "window": window,
        "payload_len": payload_len, "payload_preview": "",
        "dns": dns, "http": http, "tls": tls, "icmp": icmp, "arp": None,
        "flow": "", "flow_dir": "", "frame_len": 0, "info": "",
    }
    p["flow"], p["flow_dir"] = parser._flow_key(src, sport, dst, dport, proto)
    return p


def rules_of(hits):
    return {h["rule"] for h in hits}


def test_rst_pure_and_rst_ack():
    pkts = [
        tcp_pkt(1, flags="S", seq=0),
        tcp_pkt(2, flags="R", seq=1, sport=80, dport=12345, src="10.0.0.2", dst="10.0.0.1"),
    ]
    result = run_rules(pkts)
    hit2 = result["packet_hits"][2][0]
    assert hit2["rule"] == "rst" and hit2["severity"] == "error"
    assert "拒绝" in hit2["verdict"]


def test_rst_ack_wording():
    pkts = [tcp_pkt(1, flags="RA", seq=1, sport=80, dport=12345,
                    src="10.0.0.2", dst="10.0.0.1")]
    hit = run_rules(pkts)["packet_hits"][1][0]
    assert "RST+ACK" in hit["verdict"] and "重置" in hit["verdict"]


def test_retransmission_detected_only_on_repeat():
    pkts = [
        tcp_pkt(1, flags="PA", seq=1, payload_len=5),
        tcp_pkt(2, flags="PA", seq=1, payload_len=5),
        tcp_pkt(3, flags="PA", seq=6, payload_len=5),
    ]
    result = run_rules(pkts)
    assert 1 not in result["packet_hits"]
    assert rules_of(result["packet_hits"][2]) == {"retransmission"}
    assert 3 not in result["packet_hits"]


def test_retransmission_ignores_plain_acks():
    pkts = [
        tcp_pkt(1, flags="A", seq=1, payload_len=0),
        tcp_pkt(2, flags="A", seq=1, payload_len=0),
    ]
    assert not run_rules(pkts)["packet_hits"]


def test_zero_window_server_side_only():
    pkts = [
        tcp_pkt(0, flags="S", seq=0),
        tcp_pkt(1, flags="A", seq=10, window=0, sport=80, dport=12345,
                src="10.0.0.2", dst="10.0.0.1"),
        tcp_pkt(2, flags="A", seq=10, window=0, sport=5000, dport=80),
        tcp_pkt(3, flags="R", seq=10, window=0, sport=80, dport=12345,
                src="10.0.0.2", dst="10.0.0.1"),
    ]
    hits = run_rules(pkts)["packet_hits"]
    assert rules_of(hits[1]) == {"zero_window"}
    assert 2 not in hits
    assert rules_of(hits[3]) == {"rst"}


def test_syn_halfopen_requires_two_syn_without_reply():
    open_flow = [
        tcp_pkt(1, flags="S", seq=0),
        tcp_pkt(2, flags="SA", seq=0, sport=80, dport=12345,
                src="10.0.0.2", dst="10.0.0.1"),
    ]
    assert not run_rules(open_flow)["packet_hits"]

    half = [
        tcp_pkt(1, flags="S", seq=0, sport=12347, dport=444),
        tcp_pkt(2, flags="S", seq=0, sport=12347, dport=444),
    ]
    result = run_rules(half)["packet_hits"]
    assert rules_of(result[1]) == {"syn_halfopen"}
    assert rules_of(result[2]) == {"retransmission", "syn_halfopen"}


def test_syn_scan_threshold():
    quiet = [tcp_pkt(i + 1, flags="S", seq=0, sport=40000 + i, dport=1000 + i)
             for i in range(14)]
    assert not run_rules(quiet)["packet_hits"]

    scan = [tcp_pkt(i + 1, src="10.0.0.7", flags="S", seq=0,
                    sport=40000 + i, dport=1000 + i) for i in range(15)]
    hits = run_rules(scan)["packet_hits"]
    assert len(hits) == 15
    assert all(rules_of(h) == {"syn_scan"} for h in hits.values())


def test_dns_fail():
    dns_bad = {"qr": True, "rcode": 3, "rcode_name": "NXDOMAIN", "qname": "x.com"}
    dns_ok = {"qr": True, "rcode": 0, "rcode_name": "NOERROR", "qname": "x.com"}
    pkts = [
        tcp_pkt(1, proto="UDP", sport=53, dport=5000, dns=dns_bad),
        tcp_pkt(2, proto="UDP", sport=53, dport=5000, dns=dns_ok),
    ]
    hits = run_rules(pkts)["packet_hits"]
    assert rules_of(hits[1]) == {"dns_fail"}
    assert 2 not in hits


def test_http_error():
    err = {"type": "response", "code": 404, "reason": "Not Found"}
    ok = {"type": "response", "code": 200, "reason": "OK"}
    req = {"type": "request", "method": "GET", "path": "/"}
    pkts = [
        tcp_pkt(1, http=err), tcp_pkt(2, http=ok), tcp_pkt(3, http=req),
    ]
    hits = run_rules(pkts)["packet_hits"]
    assert rules_of(hits[1]) == {"http_error"}
    assert 2 not in hits and 3 not in hits


def test_tls_alert():
    alert = {"kind": "alert", "level": "fatal", "description": "handshake_failure", "code": 40}
    hs = {"kind": "handshake", "name": "ClientHello", "code": 1}
    pkts = [tcp_pkt(1, tls=alert), tcp_pkt(2, tls=hs)]
    hits = run_rules(pkts)["packet_hits"]
    assert rules_of(hits[1]) == {"tls_alert"}
    assert 2 not in hits


def test_icmp_error():
    bad = {"type": 3, "code": 1, "name": "目标不可达"}
    echo = {"type": 0, "code": 0, "name": "Echo 应答"}
    pkts = [
        tcp_pkt(1, proto="ICMP", icmp=bad),
        tcp_pkt(2, proto="ICMP", icmp=echo),
    ]
    hits = run_rules(pkts)["packet_hits"]
    assert rules_of(hits[1]) == {"icmp_err"}
    assert 2 not in hits
