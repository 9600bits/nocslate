import React from "react";
import { Boxes, Radar, Settings, ShieldCheck } from "lucide-react";

export default function HomePage({ onNavigate }) {
  const entries = [
    {
      id: "capture",
      icon: <Radar size={24} />,
      title: "抓包分析",
      text: "解析 pcap / pcapng，运行 TCP RST、重传、DNS 和 HTTP 等规则。",
      accent: "iris",
    },
    {
      id: "cabinets",
      icon: <Boxes size={24} />,
      title: "机柜台账",
      text: "管理机房、机柜、设备台账和 U 位占用，查看容量使用率。",
      accent: "gold",
    },
    {
      id: "security",
      icon: <ShieldCheck size={24} />,
      title: "探测与安全",
      text: "批量 Ping / HTTP / TCP 探测、暴露面资产发现和设备配置审计。",
      accent: "lake",
    },
    {
      id: "config",
      icon: <Settings size={24} />,
      title: "AI 配置",
      text: "连接 OpenAI 兼容接口，扫描可用模型并生成可读分析报告。",
      accent: "lavender",
    },
  ];

  return (
    <main className="home">
      <section className="home-hero">
        <span className="home-kicker"><ShieldCheck size={14} />数据本地处理</span>
        <h1>Packet <span>Lens</span></h1>
        <p>本地网络诊断工作台。数据不出本机，AI 仅在你主动配置后调用。</p>
      </section>
      <section className="home-grid" aria-label="功能入口">
        {entries.map((entry) => (
          <button key={entry.id} className={`home-card accent-${entry.accent}`}
                  onClick={() => onNavigate(entry.id)}>
            <span className="home-icon">{entry.icon}</span>
            <span className="home-title">{entry.title}</span>
            <span className="home-text">{entry.text}</span>
            <span className="home-go" aria-hidden="true">进入 →</span>
          </button>
        ))}
      </section>
    </main>
  );
}
