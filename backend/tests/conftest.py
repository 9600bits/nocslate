import pytest
from scapy.all import DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

IP_A = "10.0.0.1"
IP_B = "10.0.0.2"
MAC_A = "aa:bb:cc:00:00:01"
MAC_B = "aa:bb:cc:00:00:02"
MAC_EXT = "aa:bb:cc:00:00:09"


def _eth(src_ip, dst_ip, src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip)


def _tcp(src, dst, sport, dport, flags, seq, ack, win=8192, payload=b""):
    # 显式 MAC：避免 scapy 写文件时触发 ARP 解析（无 Npcap 环境会超时）
    pkt = _eth(src, dst, MAC_A, MAC_B) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=win
    )
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


@pytest.fixture()
def fixture_pcap(tmp_path):
    path = tmp_path / "fixture.pcap"
    pkts = []

    # 流 1：三次握手 + HTTP 请求 + 服务端 RST+ACK + 服务端零窗口
    pkts.append(_tcp(IP_A, IP_B, 12345, 80, "S", 0, 0))
    pkts.append(_tcp(IP_B, IP_A, 80, 12345, "SA", 0, 1))
    pkts.append(_tcp(IP_A, IP_B, 12345, 80, "A", 1, 1))
    pkts.append(_tcp(IP_A, IP_B, 12345, 80, "PA", 1, 1,
                     payload=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
    pkts.append(_tcp(IP_B, IP_A, 80, 12345, "RA", 1, 26))
    pkts.append(_tcp(IP_B, IP_A, 80, 12345, "A", 26, 2, win=0))

    # 流 2：相同 seq/len 数据段重复出现 -> 重传
    pkts.append(_tcp(IP_A, IP_B, 12346, 8080, "S", 0, 0))
    pkts.append(_tcp(IP_B, IP_A, 8080, 12346, "SA", 0, 1))
    pkts.append(_tcp(IP_A, IP_B, 12346, 8080, "PA", 1, 1, payload=b"HELLO"))
    pkts.append(_tcp(IP_A, IP_B, 12346, 8080, "PA", 1, 1, payload=b"HELLO"))

    # 流 3：两次 SYN 无任何响应 -> 半开
    pkts.append(_tcp(IP_A, IP_B, 12347, 444, "S", 0, 0))
    pkts.append(_tcp(IP_A, IP_B, 12347, 444, "S", 0, 0))

    # DNS NXDOMAIN
    pkts.append(_eth(IP_A, "8.8.8.8", MAC_A, MAC_EXT) / UDP(sport=5000, dport=53)
                / DNS(id=1, rd=1, qd=DNSQR(qname="missing.example.com")))
    pkts.append(_eth("8.8.8.8", IP_A, MAC_EXT, MAC_A) / UDP(sport=53, dport=5000)
                / DNS(id=1, qr=1, rcode=3, qd=DNSQR(qname="missing.example.com")))

    # HTTP 404
    pkts.append(_eth(IP_B, IP_A, MAC_B, MAC_A) / TCP(sport=80, dport=12348,
                flags="PA", seq=1, ack=1)
                / Raw(load=b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))

    # TLS alert: fatal handshake_failure
    tls_alert = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
    pkts.append(_eth(IP_B, IP_A, MAC_B, MAC_A) / TCP(sport=443, dport=12349,
                flags="PA", seq=1, ack=1) / Raw(load=tls_alert))

    # ICMP 主机不可达
    pkts.append(_eth("10.0.0.9", IP_A, MAC_EXT, MAC_A) / ICMP(type=3, code=1))

    # 端口扫描：同一源向 15 个不同端口发 SYN
    for i in range(15):
        pkts.append(_tcp("10.0.0.7", IP_B, 40000 + i, 1000 + i, "S", 0, 0))

    wrpcap(str(path), pkts)
    return path
