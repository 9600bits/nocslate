import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Home, Radar, Settings, Sun, Moon, Boxes, ShieldCheck } from "lucide-react";
import { fetchRules, fetchConfig, fetchPackets, fetchPacketDetail, uploadPcap } from "./api";
import HomePage from "./components/HomePage.jsx";
import SecurityOpsPage from "./components/SecurityOpsPage.jsx";
import CabinetPage from "./components/CabinetPage.jsx";
import Toolbar from "./components/Toolbar.jsx";
import UploadZone from "./components/UploadZone.jsx";
import PacketTable from "./components/PacketTable.jsx";
import DetailDrawer from "./components/DetailDrawer.jsx";
import AiPanel from "./components/AiPanel.jsx";
import ConfigDialog from "./components/ConfigDialog.jsx";

const PAGE_LIMIT = 200;
const BLANK_FILTERS = { proto: "", rule: "", q: "", hits_only: false };

function routeFromHash() {
  const value = window.location.hash.replace(/^#\/?/, "");
  return ["home", "capture", "probe", "cabinets", "security"].includes(value) ? value : "home";
}

export default function App() {
  const [route, setRoute] = useState(routeFromHash);
  const [theme, setTheme] = useState(() => document.documentElement.dataset.theme || "dark");
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
  const [lastFlow, setLastFlow] = useState(null);
  const listRequestSeq = useRef(0);

  useEffect(() => {
    const onHashChange = () => setRoute(routeFromHash());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("packet-lens-theme", theme);
  }, [theme]);

  useEffect(() => {
    fetchRules().then((data) => setRules(data.rules)).catch(() => {});
    fetchConfig().then(setCfg).catch(() => {});
  }, []);

  useEffect(() => {
    if (!session || route !== "capture") return undefined;
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
    window.location.hash = `#/${target}`;
  }, []);

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
            <div className="brand-name">Packet Lens</div>
            <div className="brand-sub">抓包分析 · 探测与安全 · AI 解读</div>
          </div>
        </button>
        <nav className="main-nav" aria-label="主导航">
          <button className={route === "home" ? "nav-item on" : "nav-item"} onClick={() => navigate("home")}>
            <Home size={15} /> 首页
          </button>
          <button className={route === "capture" ? "nav-item on" : "nav-item"} onClick={() => navigate("capture")}>
            <Radar size={15} /> 抓包分析
          </button>
          <button className={route === "cabinets" ? "nav-item on" : "nav-item"} onClick={() => navigate("cabinets")}>
            <Boxes size={15} /> 机柜台账
          </button>
          <button className={route === "probe" || route === "security" ? "nav-item on" : "nav-item"}
                  onClick={() => navigate("security")}>
            <ShieldCheck size={15} /> 探测与安全
          </button>
        </nav>
        <div className="header-actions">
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

      {route === "home" && <HomePage onNavigate={navigate} />}
      {route === "cabinets" && <CabinetPage />}
      {(route === "probe" || route === "security") && (
        <SecurityOpsPage
          key={route === "security" ? "security" : "probe"}
          cfg={cfg}
          onNavigate={navigate}
          onOpenConfig={() => setConfigOpen(true)}
          initialTab={route === "security" ? "exposure" : "probe"}
        />
      )}
      {route === "capture" && (
        !session ? (
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
        )
      )}

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
