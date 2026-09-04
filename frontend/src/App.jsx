import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Activity, Home, Radar, Settings, Sun, Moon, Boxes, ShieldCheck, ServerCog, Bell, Network, LockKeyhole, GitBranch, BookOpen } from "lucide-react";
import { fetchRules, fetchConfig, fetchPackets, fetchPacketDetail, uploadPcap } from "./api";
import HomePage from "./components/HomePage.jsx";
import CabinetPage from "./components/CabinetPage.jsx";
import Toolbar from "./components/Toolbar.jsx";
import UploadZone from "./components/UploadZone.jsx";
import PacketTable from "./components/PacketTable.jsx";
import DetailDrawer from "./components/DetailDrawer.jsx";
import AiPanel from "./components/AiPanel.jsx";
import ConfigDialog from "./components/ConfigDialog.jsx";
import InfraWorkspace from "./components/InfraWorkspace.jsx";
import WorkspaceShell from "./components/WorkspaceShell.jsx";
import NetworkWorkspace from "./components/NetworkWorkspace.jsx";
import SecurityWorkspace from "./components/SecurityWorkspace.jsx";
import { infra } from "./api";

const PAGE_LIMIT = 200;
const BLANK_FILTERS = { proto: "", rule: "", q: "", hits_only: false };
const WORKSPACES = [
  { id: "network", label: "网络分析", icon: Network },
  { id: "assets", label: "资产与连接", icon: ServerCog },
  { id: "security", label: "安全中心", icon: ShieldCheck },
  { id: "planning", label: "规划与诊断", icon: GitBranch },
  { id: "knowledge", label: "知识与 AI", icon: BookOpen },
];
const NETWORK_TABS = [
  { id: "probe", href: "network/probe", label: "探测与监控", icon: Network },
  { id: "capture", href: "network/capture", label: "抓包分析", icon: Radar },
];
const ASSET_TABS = [
  { id: "servers", href: "assets/servers", label: "服务器巡检", icon: ServerCog },
  { id: "cabinets", href: "assets/cabinets", label: "机柜台账", icon: Boxes },
  { id: "credentials", href: "assets/credentials", label: "连接与凭据", icon: LockKeyhole },
];
const PLANNING_TABS = [
  { id: "network", href: "planning/ip-vlan", label: "IP / VLAN 规划", icon: GitBranch },
  { id: "diagnostics", href: "planning/diagnostics", label: "一键诊断", icon: Activity },
];

const ROUTE_ALIASES = {
  capture: "network/capture", probe: "network/probe", cabinets: "assets/cabinets", security: "security/exposure",
  "infra/servers": "assets/servers", "infra/credentials": "assets/credentials",
  "infra/diagnostics": "planning/diagnostics", "infra/network": "planning/ip-vlan", "infra/knowledge": "knowledge",
};

function canonicalRoute(value) {
  const raw = String(value || "").replace(/^#\/?/, "");
  if (ROUTE_ALIASES[raw]) return ROUTE_ALIASES[raw];
  if (raw === "network") return "network/probe";
  if (raw === "assets") return "assets/servers";
  if (raw === "planning") return "planning/ip-vlan";
  if (raw === "security") return "security/exposure";
  if (["home", "knowledge"].includes(raw)) return raw;
  if (/^(network|assets|security|planning)\/.+/.test(raw)) return raw;
  return "home";
}

function routeFromHash() { return canonicalRoute(window.location.hash); }

export default function App() {
  const [route, setRoute] = useState(routeFromHash);
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || "light");
  const [rules, setRules] = useState([]);
  const [cfg, setCfg] = useState(null);
  const [configOpen, setConfigOpen] = useState(false);
  const [session, setSession] = useState(null);
  const [rows, setRows] = useState([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [filters, setFilters] = useState(BLANK_FILTERS);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState("");
  const [selection, setSelection] = useState(() => new Set());
  const [activeNo, setActiveNo] = useState(null);
  const [detail, setDetail] = useState(null);
  const [openEvents, setOpenEvents] = useState(0);
  const [lastFlow, setLastFlow] = useState(null);
  const listRequestSeq = useRef(0);

  useEffect(() => {
    const onHashChange = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("nocslate-theme", theme);
  }, [theme]);

  useEffect(() => {
    fetchRules().then((data) => setRules(data.rules)).catch(() => {});
    fetchConfig().then(setCfg).catch(() => {});
    infra.events().then((data) => setOpenEvents((data.events || []).length)).catch(() => {});
  }, []);

  useEffect(() => {
    if (!session || route !== "network/capture") return undefined;
    const controller = new AbortController();
    const requestNo = ++listRequestSeq.current;
    setLoading(true);
    const timer = setTimeout(async () => {
      try {
        const data = await fetchPackets({
          session_id: session.session_id,
          offset,
          limit: PAGE_LIMIT,
          proto: filters.proto,
          rule: filters.rule,
          q: filters.q,
          hits_only: filters.hits_only,
        }, controller.signal);
        if (requestNo !== listRequestSeq.current) return;
        setRows(data.packets);
        setTotal(data.total);
        setOffset(offset);
      } catch (err) {
        if (err?.name !== "AbortError") setUploadError(String(err.message || err));
      } finally {
        if (requestNo === listRequestSeq.current) setLoading(false);
      }
    }, 250);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [session, offset, filters, route]);

  const navigate = useCallback((target) => {
    if (target === "config") {
      if (routeFromHash() !== "home") window.location.hash = "#/home";
      setRoute("home");
      setConfigOpen(true);
      return;
    }
    window.location.hash = `#/${canonicalRoute(target)}`;
  }, []);

  const networkRoute = route.startsWith("network/") ? route.slice("network/".length) : "probe";
  const assetRoute = route.startsWith("assets/") ? route.slice("assets/".length) : "servers";
  const planningRoute = route.startsWith("planning/") ? route.slice("planning/".length) : "network";
  const securityRoute = route.startsWith("security/") ? route.slice("security/".length) : "exposure";

  const handleFile = useCallback(async (file) => {
    if (!file) return;
    navigate("capture");
    setUploading(true);
    setUploadError("");
    try {
      const response = await uploadPcap(file);
      setSession(response);
      setSelection(new Set());
      setActiveNo(null);
      setDetail(null);
      setLastFlow(null);
      setOffset(0);
      setFilters(BLANK_FILTERS);
    } catch (err) {
      setUploadError(String(err.message || err));
    } finally {
      setUploading(false);
    }
  }, [navigate]);

  const toggleRow = useCallback((no) => {
    setSelection((prev) => {
      const next = new Set(prev);
      if (next.has(no)) next.delete(no); else next.add(no);
      return next;
    });
  }, []);

  const openRow = useCallback((row) => {
    if (!session) return;
    setActiveNo(row.no);
    setLastFlow(row.flow);
    fetchPacketDetail(session.session_id, row.no)
      .then(setDetail)
      .catch(() => setDetail(null));
  }, [session]);

  const resetAll = useCallback(() => {
    setSession(null);
    setRows([]);
    setTotal(0);
    setSelection(new Set());
    setActiveNo(null);
    setDetail(null);
    setLastFlow(null);
    setFilters(BLANK_FILTERS);
    setOffset(0);
    navigate("home");
  }, [navigate]);

  const ruleNames = useMemo(() => {
    const map = {};
    for (const rule of rules) map[rule.id] = rule;
    return map;
  }, [rules]);

  const totalHits = useMemo(() => {
    if (!session) return 0;
    return Object.values(session.rule_summary || {}).reduce((sum, count) => sum + count, 0);
  }, [session]);

  const errorCount = useMemo(() => {
    if (!session || !ruleNames) return 0;
    return Object.entries(session.rule_summary || {})
      .filter(([id]) => ruleNames[id]?.severity === "error")
      .reduce((sum, [, count]) => sum + count, 0);
  }, [session, ruleNames]);

  return (
    <div className="app">
      <header className="app-header">
        <button className="brand brand-button" onClick={() => navigate("home")} title="返回首页">
          <div className="brand-icon"><Radar size={18} /></div>
          <div>
            <div className="brand-name">NOCSlate</div>
            <div className="brand-sub">本地运维工作台 · 网络 · 资产 · 安全</div>
          </div>
        </button>
        <nav className="main-nav" aria-label="主导航">
          <button className={route === "home" ? "nav-item on" : "nav-item"} onClick={() => navigate("home")}>
            <Home size={15} /> 首页
          </button>
          {WORKSPACES.map(({ id, label, icon: Icon }) => <button key={id} className={route === id || route.startsWith(`${id}/`) ? "nav-item on" : "nav-item"} onClick={() => navigate(id)}>
            <Icon size={15} /> {label}
          </button>)}
        </nav>
        <div className="header-actions">
          <button className="btn btn-ghost btn-icon-only event-button" title="事件中心" onClick={() => navigate("security/events")} aria-label="事件中心">
            <Bell size={17} />{openEvents > 0 && <span className="event-count">{openEvents > 99 ? "99+" : openEvents}</span>}
          </button>
          <button className="btn btn-ghost theme-toggle" title={theme === "dark" ? "切换明亮主题" : "切换暗色主题"}
                  onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
                  aria-label={theme === "dark" ? "切换明亮主题" : "切换暗色主题"}>
            {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
          </button>
          <button className="btn btn-ghost btn-icon-only" title="AI 配置"
                  onClick={() => setConfigOpen(true)} aria-label="AI 配置">
            <Settings size={17} />
          </button>
        </div>
      </header>

      {route === "home" && <HomePage onNavigate={navigate} cfg={cfg} />}
      {route === "network/probe" && <NetworkWorkspace cfg={cfg} onNavigate={navigate} onOpenConfig={() => setConfigOpen(true)} route="probe" />}
      {route === "network/capture" && <WorkspaceShell label="网络分析" tabs={NETWORK_TABS} active="capture"><>
        {!session ? (
          <UploadZone onFile={handleFile} uploading={uploading} error={uploadError} />
        ) : (
          <div className="app-body">
            <div className="main-pane">
              <Toolbar
                session={session}
                rules={rules}
                filters={filters}
                onFilters={setFilters}
                onFile={handleFile}
                uploading={uploading}
                onReset={resetAll}
                totalHits={totalHits}
                errorCount={errorCount}
              />
              <div className="table-wrap">
                {loading && <div className="loading-bar" />}
                <PacketTable
                  rows={rows}
                  selection={selection}
                  activeNo={activeNo}
                  onToggle={toggleRow}
                  onRowClick={openRow}
                />
              </div>
              <div className="table-footer">
                <span>
                  第 {total === 0 ? 0 : offset + 1}–{Math.min(offset + PAGE_LIMIT, total)} 条 / 共 {total} 条
                </span>
                <span className="grow" />
                <button className="btn btn-ghost" disabled={offset <= 0 || loading}
                        onClick={() => setOffset(Math.max(0, offset - PAGE_LIMIT))}>
                  上一页
                </button>
                <button className="btn btn-ghost" disabled={offset + PAGE_LIMIT >= total || loading}
                        onClick={() => setOffset(offset + PAGE_LIMIT)}>
                  下一页
                </button>
              </div>
            </div>
            <AiPanel
              session={session}
              cfg={cfg}
              selection={[...selection].sort((a, b) => a - b)}
              lastFlow={lastFlow}
              onOpenConfig={() => setConfigOpen(true)}
            />
          </div>
        )}
      </></WorkspaceShell>}
      {route === "assets/cabinets" && <WorkspaceShell label="资产与连接" tabs={ASSET_TABS} active="cabinets"><CabinetPage /></WorkspaceShell>}
      {(route === "assets/servers" || route === "assets/credentials") && <WorkspaceShell label="资产与连接" tabs={ASSET_TABS} active={assetRoute}><InfraWorkspace embedded section="assets" route={assetRoute} /></WorkspaceShell>}
      {route.startsWith("security/") && <SecurityWorkspace route={securityRoute} cfg={cfg} onNavigate={navigate} onOpenConfig={() => setConfigOpen(true)} />}
      {route.startsWith("planning/") && <WorkspaceShell label="规划与诊断" tabs={PLANNING_TABS} active={planningRoute === "ip-vlan" ? "network" : "diagnostics"}><InfraWorkspace embedded section="planning" route={planningRoute === "ip-vlan" ? "network" : planningRoute} /></WorkspaceShell>}
      {route === "knowledge" && <WorkspaceShell label="知识与 AI" tabs={[{ id: "knowledge", href: "knowledge", label: "知识与 AI", icon: BookOpen }]} active="knowledge"><InfraWorkspace embedded section="knowledge" route="knowledge" /></WorkspaceShell>}
      {detail && (
        <DetailDrawer detail={detail} ruleNames={ruleNames} onClose={() => setDetail(null)} />
      )}
      {configOpen && (
        <ConfigDialog
          cfg={cfg}
          onClose={() => setConfigOpen(false)}
          onSaved={(value) => { setCfg(value); setConfigOpen(false); }}
        />
      )}
    </div>
  );
}
