import React, { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, ArrowUpRight, BookOpen, CheckCircle2, GitBranch,
  Network, Radar, ServerCog, ShieldAlert, ShieldCheck, UploadCloud,
} from "lucide-react";
import { infra } from "../api";

const WORKSPACES = [
  { id: "network/capture", icon: Radar, title: "网络分析", text: "抓包解析、网络探测与定时监控。", accent: "iris" },
  { id: "assets/servers", icon: ServerCog, title: "资产与连接", text: "机柜、服务器巡检、SSH / RDP 和凭据。", accent: "lake" },
  { id: "security/exposure", icon: ShieldCheck, title: "安全中心", text: "暴露面发现、配置审计与异常事件。", accent: "coral" },
  { id: "planning/ip-vlan", icon: GitBranch, title: "规划与诊断", text: "IP / VLAN 规划和一键故障诊断。", accent: "gold" },
  { id: "knowledge", icon: BookOpen, title: "知识与 AI", text: "本地知识库、运行摘要和 AI 助手。", accent: "lavender" },
];

function useDashboard() {
  const [state, setState] = useState({ loading: true, data: null });
  const reload = () => {
    setState({ loading: true, data: null });
    Promise.all([infra.events(), infra.servers(), infra.diagnostics(), infra.networkPlans()])
      .then(([events, servers, diagnostics, plans]) => setState({ loading: false, data: {
        events: events.events || [], servers: servers.servers || [],
        runs: diagnostics.runs || [], plans: plans.plans || [],
      }}))
      .catch(() => setState({ loading: false, data: { events: [], servers: [], runs: [], plans: [] } }));
  };
  useEffect(reload, []);
  return [state, reload];
}

function Stat({ icon: Icon, label, value, tone = "" }) {
  return <div className={`dashboard-stat ${tone}`}><Icon size={16} /><div><b>{value}</b><span>{label}</span></div></div>;
}

export default function HomePage({ onNavigate, cfg }) {
  const [{ loading, data }, reload] = useDashboard();
  const events = data?.events || [];
  const servers = data?.servers || [];
  const runs = data?.runs || [];
  const plans = data?.plans || [];
  const latestInspection = useMemo(() => servers.map((item) => item.last_inspection).filter(Boolean)
    .sort((a, b) => String(b.started_at).localeCompare(String(a.started_at)))[0], [servers]);
  const latestRun = runs[0];

  return <main className="home dashboard-home">
    <section className="dashboard-hero">
      <div><span className="home-kicker"><ShieldCheck size={14} />本地运维工作台</span><h1>Packet <span>Lens</span></h1><p>从网络数据、资产状态到安全事件，在一个工作台完成定位与规划。</p></div>
      <div className="dashboard-actions">
        <button className="btn btn-primary" onClick={() => onNavigate("network/capture")}><UploadCloud size={15} />上传抓包</button>
        <button className="btn" onClick={() => onNavigate("planning/ip-vlan")}><GitBranch size={15} />新建 IP / VLAN</button>
        <button className="btn" onClick={() => onNavigate("planning/diagnostics")}><Activity size={15} />新建诊断</button>
        <button className="btn" onClick={() => onNavigate("assets/servers")}><ServerCog size={15} />登记服务器</button>
      </div>
    </section>
    <section className="dashboard-stats" aria-label="运行状态">
      <Stat icon={AlertTriangle} label="待处理事件" value={loading ? "…" : events.length} tone={events.length ? "danger" : "ok"} />
      <Stat icon={ServerCog} label="登记服务器" value={loading ? "…" : servers.length} />
      <Stat icon={CheckCircle2} label="最近巡检" value={loading ? "…" : latestInspection?.status || "未运行"} />
      <Stat icon={Activity} label="最近诊断" value={loading ? "…" : latestRun?.status || "未运行"} />
      <Stat icon={GitBranch} label="网络规划" value={loading ? "…" : plans.length} />
      <Stat icon={ShieldAlert} label="AI 状态" value={cfg ? (cfg.has_key ? "已配置" : "未配置") : "检查中"} tone="ai" />
    </section>
    <section className="dashboard-grid">
      <div className="dashboard-panel"><div className="dashboard-panel-head"><div><span className="eyebrow">ATTENTION</span><h2>待处理事件</h2></div><button className="btn btn-ghost" onClick={() => onNavigate("security/events")}>查看全部 <ArrowUpRight size={14} /></button></div>
        {events.length ? <div className="dashboard-list">{events.slice(0, 5).map((event) => <button className="dashboard-list-row" key={event.id} onClick={() => onNavigate("security/events")}><span className={`status-dot ${event.severity === "error" ? "warn" : "on"}`} /><span><b>{event.title}</b><small>{event.source_type} · {event.created_at}</small></span><ArrowUpRight size={14} /></button>)}</div> : <div className="dashboard-empty"><CheckCircle2 size={18} />暂无待处理事件</div>}
      </div>
      <div className="dashboard-panel"><div className="dashboard-panel-head"><div><span className="eyebrow">RECENT ACTIVITY</span><h2>最近活动</h2></div><button className="btn btn-ghost btn-icon-only" title="刷新" onClick={reload}><Activity size={15} /></button></div>
        {runs.length || plans.length ? <div className="dashboard-list">{[...runs.slice(0, 3).map((item) => ({ ...item, kind: "诊断", href: "planning/diagnostics" })), ...plans.slice(0, 2).map((item) => ({ ...item, kind: "网络规划", href: "planning/ip-vlan" }))].slice(0, 5).map((item) => <button className="dashboard-list-row" key={`${item.kind}-${item.id}`} onClick={() => onNavigate(item.href)}><span className="activity-icon">{item.kind === "诊断" ? <Activity size={14} /> : <Network size={14} />}</span><span><b>{item.kind} · {item.name || item.target}</b><small>{item.updated_at || item.started_at}</small></span><ArrowUpRight size={14} /></button>)}</div> : <div className="dashboard-empty">还没有运行记录</div>}
      </div>
    </section>
    <section className="dashboard-workspaces"><div className="dashboard-panel-head"><div><span className="eyebrow">WORKSPACES</span><h2>工作域</h2></div></div><div className="home-grid">{WORKSPACES.map(({ id, icon: Icon, title, text, accent }) => <button key={id} className={`home-card accent-${accent}`} onClick={() => onNavigate(id)}><span className="home-icon"><Icon size={23} /></span><span className="home-title">{title}</span><span className="home-text">{text}</span><span className="home-go" aria-hidden="true">进入 <ArrowUpRight size={13} /></span></button>)}</div></section>
  </main>;
}
