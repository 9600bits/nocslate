import React, { useMemo, useRef, useState } from "react";
import {
  ArrowLeft, Bot, Copy, Download, FileSearch, Network, Play, ShieldAlert,
  ShieldCheck, Square, Upload,
} from "lucide-react";
import {
  fetchOfflineExposureReport, streamConfigAuditAnalyze, streamExposure,
  streamExposureAnalyze, uploadConfigAudit,
} from "../api";
import Markdown from "./Markdown.jsx";

const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
  1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432,
  5900, 6379, 8080, 8443, 9200, 11211, 27017,
];

const SEVERITY_CLASS = {
  critical: "err",
  high: "err",
  medium: "warn",
  low: "info",
};

const SEVERITY_LABEL = {
  critical: "严重",
  high: "高",
  medium: "中",
  low: "低",
};

const ASSET_STATUS_LABEL = {
  alive: "存活",
  assumed: "直接检查",
  timeout: "无应答",
  unreachable: "不可达",
  error: "错误",
};

function parseTargets(text) {
  return [...new Set(
    text.split(/[\n,，;；]+/).map((s) => s.trim()).filter(Boolean),
  )].slice(0, 256);
}

function parsePorts(text) {
  const ports = [];
  for (const part of text.split(/[\n,，;；\s]+/)) {
    const value = part.trim();
    if (!value) continue;
    if (value.includes("-")) {
      const [a, b] = value.split("-").map(Number);
      if (Number.isInteger(a) && Number.isInteger(b) && a > 0 && b <= 65535 && a <= b) {
        for (let port = a; port <= b && ports.length < 8192; port += 1) ports.push(port);
      }
    } else {
      const port = Number(value);
      if (Number.isInteger(port) && port > 0 && port <= 65535) ports.push(port);
    }
  }
  return [...new Set(ports)].slice(0, 8192);
}

function upsertResult(list, result) {
  const identity = result.type === "asset"
    ? `asset:${result.target}`
    : `endpoint:${result.target}:${result.port}`;
  const next = list.filter((item) => {
    const key = item.type === "asset"
      ? `asset:${item.target}`
      : `endpoint:${item.target}:${item.port}`;
    return key !== identity;
  });
  return [...next, result];
}

function clamp(value, min, max, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

function riskLevel(counts) {
  if (counts?.critical || counts?.high) return "err";
  if (counts?.medium) return "warn";
  return "ok";
}

function ReportPane({ reportMode, offlineOutput, aiOutput, busy, canUseAi, onMode, onRun, onStop,
                      error, output, onCopy, onDownload }) {
  return (
    <section className="panel analysis-panel">
      <div className="panel-head">
        {reportMode === "offline" ? <FileSearch size={16} /> : <Bot size={16} />}
        <h3>{reportMode === "offline" ? "本地离线报告" : "AI 增强解读"}</h3>
        <div className="scope-seg report-switch">
          <button className={reportMode === "offline" ? "on" : ""} onClick={() => onMode("offline")}>离线</button>
          <button className={reportMode === "ai" ? "on" : ""} onClick={() => onMode("ai")}>AI</button>
        </div>
      </div>
      {busy ? (
        <button className="btn ai-run" onClick={onStop}><Square size={14} /> 停止</button>
      ) : (
        <button className="btn btn-primary ai-run" onClick={onRun}>
          <Play size={14} /> {reportMode === "offline" ? "生成离线报告" : "开始 AI 解读"}
        </button>
      )}
      {reportMode === "ai" && !canUseAi && (
        <div className="ai-error">AI 未配置；离线报告不需要网络，可继续使用。</div>
      )}
      {error && <div className="ai-error">{error}</div>}
      <div className="markdown-output analysis-output" aria-live="polite">
        {output ? <Markdown text={output} streaming={busy && reportMode === "ai"} />
          : <span className="placeholder">结果将显示在这里</span>}
      </div>
      <div className="ai-footer">
        <span className="stream-note">{reportMode === "offline" ? "本地规则生成" : "AI 增强输出"}</span>
        <span className="grow" />
        <button className="btn btn-ghost btn-icon-only" disabled={!output} onClick={onCopy} title="复制报告" aria-label="复制报告">
          <Copy size={15} />
        </button>
        <button className="btn btn-ghost btn-icon-only" disabled={!output} onClick={onDownload} title="下载 Markdown" aria-label="下载 Markdown">
          <Download size={15} />
        </button>
      </div>
    </section>
  );
}

export default function SecurityPage({
  cfg,
  onNavigate,
  onOpenConfig,
  embedded = false,
  activeTab,
  onTabChange,
}) {
  const [internalTab, setInternalTab] = useState(activeTab || "exposure");
  const tab = activeTab || internalTab;
  const setTab = (value) => {
    if (onTabChange) onTabChange(value);
    else setInternalTab(value);
  };
  const [targetsText, setTargetsText] = useState("127.0.0.1\n192.168.1.1");
  const [portText, setPortText] = useState(DEFAULT_PORTS.join(", "));
  const [discoverHosts, setDiscoverHosts] = useState(true);
  const [pingCount, setPingCount] = useState(2);
  const [pingTimeout, setPingTimeout] = useState(1000);
  const [tcpTimeout, setTcpTimeout] = useState(2);
  const [serviceTimeout, setServiceTimeout] = useState(2);
  const [concurrency, setConcurrency] = useState(64);
  const [tcpConcurrency, setTcpConcurrency] = useState(128);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState([]);
  const [summary, setSummary] = useState(null);
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [runError, setRunError] = useState("");
  const [reportMode, setReportMode] = useState("offline");
  const [offlineOutput, setOfflineOutput] = useState("");
  const [offlineError, setOfflineError] = useState("");
  const [offlineBusy, setOfflineBusy] = useState(false);
  const [aiOutput, setAiOutput] = useState("");
  const [aiError, setAiError] = useState("");
  const [aiBusy, setAiBusy] = useState(false);
  const scanAbort = useRef(null);
  const reportAbort = useRef(null);

  const [auditFile, setAuditFile] = useState(null);
  const [audit, setAudit] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [auditError, setAuditError] = useState("");
  const [auditReportMode, setAuditReportMode] = useState("offline");
  const [auditAiOutput, setAuditAiOutput] = useState("");
  const [auditAiError, setAuditAiError] = useState("");
  const [auditAiBusy, setAuditAiBusy] = useState(false);
  const auditAbort = useRef(null);

  const targets = useMemo(() => parseTargets(targetsText), [targetsText]);
  const ports = useMemo(() => parsePorts(portText), [portText]);
  const hasKey = cfg?.has_key;

  const assets = useMemo(() => results.filter((item) => item.type === "asset"), [results]);
  const endpoints = useMemo(() => results.filter((item) => item.type === "exposure"), [results]);
  const findings = useMemo(() => endpoints.flatMap((endpoint) => (
    (endpoint.findings || []).map((finding) => ({ ...finding, endpoint: endpoint.endpoint, service: endpoint.service }))
  )), [endpoints]);
  const riskCounts = useMemo(() => {
    const counts = {};
    for (const finding of findings) counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    return counts;
  }, [findings]);
  const reportOutput = reportMode === "offline" ? offlineOutput : aiOutput;
  const reportError = reportMode === "offline" ? offlineError : aiError;
  const reportBusy = reportMode === "offline" ? offlineBusy : aiBusy;
  const canReport = Boolean(summary);

  const downloadMarkdown = (content, name) => {
    if (!content) return;
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${name}-${stamp}.md`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const runExposure = async () => {
    if (!targets.length || running) return;
    setRunning(true);
    setResults([]);
    setSummary(null);
    setRunError("");
    setOfflineOutput("");
    setOfflineError("");
    setAiOutput("");
    setAiError("");
    setProgress({ done: 0, total: targets.length });
    const controller = new AbortController();
    scanAbort.current = controller;
    const body = {
      targets,
      ports,
      discover_hosts: discoverHosts,
      ping_count: clamp(pingCount, 1, 5, 2),
      ping_timeout_ms: clamp(pingTimeout, 100, 5000, 1000),
      tcp_timeout_s: Math.min(10, Math.max(0.5, Number(tcpTimeout) || 2)),
      service_timeout_s: Math.min(10, Math.max(0.5, Number(serviceTimeout) || 2)),
      concurrency: clamp(concurrency, 1, 256, 64),
      tcp_concurrency: clamp(tcpConcurrency, 1, 512, 128),
    };
    try {
      await streamExposure(body, {
        onEvent: (event) => {
          if (event.type === "start") setProgress({ done: 0, total: event.target_total || 0 });
          if (event.type === "result") {
            setResults((prev) => upsertResult(prev, event.result));
            setProgress({ done: event.done || 0, total: event.total || 0 });
          }
          if (event.type === "progress") setProgress({ done: event.done || 0, total: event.total || 0 });
          if (event.type === "summary") {
            setSummary(event);
            setResults((prev) => {
              let next = prev;
              for (const asset of event.assets || []) next = upsertResult(next, asset);
              return next;
            });
          }
          if (event.type === "error") setRunError(event.message);
        },
        onError: (message) => setRunError(message),
      }, controller.signal);
    } catch (err) {
      if (err?.name !== "AbortError") setRunError(String(err.message || err));
    } finally {
      setRunning(false);
      scanAbort.current = null;
    }
  };

  const stopExposure = () => scanAbort.current?.abort();

  const runExposureReport = async () => {
    if (!summary || reportBusy) return;
    const payload = { summary, assets, findings };
    if (reportMode === "offline") {
      setOfflineOutput("");
      setOfflineError("");
      setOfflineBusy(true);
      try {
        const data = await fetchOfflineExposureReport(payload);
        setOfflineOutput(data.markdown);
      } catch (err) {
        setOfflineError(String(err.message || err));
      } finally {
        setOfflineBusy(false);
      }
      return;
    }
    setAiOutput("");
    setAiError("");
    setAiBusy(true);
    const controller = new AbortController();
    reportAbort.current = controller;
    let acc = "";
    try {
      await streamExposureAnalyze(payload, {
        onEvent: (event) => {
          if (event.delta) { acc += event.delta; setAiOutput(acc); }
          if (event.error) setAiError((prev) => prev || event.error);
        },
        onError: (message) => setAiError((prev) => prev || message),
      }, controller.signal);
    } catch (err) {
      if (err?.name !== "AbortError") setAiError(String(err.message || err));
    } finally {
      setAiBusy(false);
      reportAbort.current = null;
    }
  };

  const submitAudit = async () => {
    const file = auditFile;
    if (!file || uploading) return;
    setUploading(true);
    setAuditError("");
    setAudit(null);
    setAuditAiOutput("");
    setAuditAiError("");
    try {
      const data = await uploadConfigAudit(file);
      setAudit(data);
    } catch (err) {
      setAuditError(String(err.message || err));
    } finally {
      setUploading(false);
    }
  };

  const runAuditAi = async () => {
    if (!audit || auditAiBusy) return;
    setAuditAiOutput("");
    setAuditAiError("");
    setAuditAiBusy(true);
    const controller = new AbortController();
    auditAbort.current = controller;
    let acc = "";
    try {
      await streamConfigAuditAnalyze({ result: audit }, {
        onEvent: (event) => {
          if (event.delta) { acc += event.delta; setAuditAiOutput(acc); }
          if (event.error) setAuditAiError((prev) => prev || event.error);
        },
        onError: (message) => setAuditAiError((prev) => prev || message),
      }, controller.signal);
    } catch (err) {
      if (err?.name !== "AbortError") setAuditAiError(String(err.message || err));
    } finally {
      setAuditAiBusy(false);
      auditAbort.current = null;
    }
  };

  const percent = progress.total ? Math.round((progress.done / progress.total) * 100) : 0;
  const riskClass = riskLevel(riskCounts);

  const content = (
    <>
      {!embedded && (
        <>
          <div className="page-head">
            <button className="btn btn-ghost" onClick={() => onNavigate("home")}>
              <ArrowLeft size={15} /> 返回首页
            </button>
            <div className="page-title">
              <ShieldCheck size={18} className="accent-iris" />
              <h2>安全审计</h2>
            </div>
            <span className="legal-note">仅用于你有权测试的网络</span>
          </div>

          <div className="seg tabs page-tabs" role="tablist" aria-label="安全功能">
            <button role="tab" aria-selected={tab === "exposure"} className={tab === "exposure" ? "on" : ""}
                    onClick={() => setTab("exposure")}>
              <Network size={15} /> 暴露面 / 资产发现
            </button>
            <button role="tab" aria-selected={tab === "config"} className={tab === "config" ? "on" : ""}
                    onClick={() => setTab("config")}>
              <ShieldAlert size={15} /> 设备配置审计
            </button>
          </div>
        </>
      )}

      {tab === "exposure" && (
        <div className="security-layout">
          <section className="probe-config">
            <label className="field-label" htmlFor="security-targets">目标（每行一个）</label>
            <textarea id="security-targets" className="input textarea" rows={6}
                      value={targetsText} onChange={(event) => setTargetsText(event.target.value)}
                      placeholder="192.168.1.10&#10;web.example.com" />
            <div className="counter-note">{targets.length}/256 个目标</div>

            <label className="field-label" htmlFor="security-ports">暴露端口</label>
            <textarea id="security-ports" className="input textarea ports-textarea" rows={8}
                      value={portText} onChange={(event) => setPortText(event.target.value)} />
            <div className="counter-note">{ports.length} 个端口，组合上限 8192</div>

            <label className="check-field">
              <input type="checkbox" checked={discoverHosts}
                     onChange={(event) => setDiscoverHosts(event.target.checked)} />
              <span>先做 Ping 存活探测</span>
            </label>

            {running ? (
              <button className="btn btn-stop" onClick={stopExposure}><Square size={14} /> 停止扫描</button>
            ) : (
              <button className="btn btn-primary" onClick={runExposure} disabled={!targets.length || !ports.length}>
                <Play size={14} /> 开始暴露面扫描
              </button>
            )}
            {running && (
              <div className="progress">
                <div className="progress-bar" style={{ width: `${percent}%` }} />
              </div>
            )}
            {runError && <div className="ai-error">{runError}</div>}

            <details className="advanced">
              <summary>高级设置</summary>
              <div className="advanced-grid">
                <label className="compact-field"><span>Ping 次数</span>
                  <input className="input" type="number" min="1" max="5" value={pingCount}
                         onChange={(event) => setPingCount(Number(event.target.value))} /></label>
                <label className="compact-field"><span>Ping 超时 ms</span>
                  <input className="input" type="number" min="100" max="5000" step="100" value={pingTimeout}
                         onChange={(event) => setPingTimeout(Number(event.target.value))} /></label>
                <label className="compact-field"><span>TCP 超时 s</span>
                  <input className="input" type="number" min="0.5" max="10" step="0.5" value={tcpTimeout}
                         onChange={(event) => setTcpTimeout(Number(event.target.value))} /></label>
                <label className="compact-field"><span>服务识别超时 s</span>
                  <input className="input" type="number" min="0.5" max="10" step="0.5" value={serviceTimeout}
                         onChange={(event) => setServiceTimeout(Number(event.target.value))} /></label>
                <label className="compact-field"><span>存活并发</span>
                  <input className="input" type="number" min="1" max="256" value={concurrency}
                         onChange={(event) => setConcurrency(Number(event.target.value))} /></label>
                <label className="compact-field"><span>TCP 并发</span>
                  <input className="input" type="number" min="1" max="512" value={tcpConcurrency}
                         onChange={(event) => setTcpConcurrency(Number(event.target.value))} /></label>
              </div>
            </details>
          </section>

          <div className="security-results">
            <section className="panel">
              <div className="panel-head"><ShieldCheck size={16} /><h3>扫描结果</h3></div>
              <div className="result-stats five">
                <div><span>目标</span><b>{summary?.targets_total ?? targets.length}</b></div>
                <div><span>存活</span><b>{summary?.hosts_alive ?? assets.filter((item) => item.status === "alive").length}</b></div>
                <div><span>开放端口</span><b>{summary?.open_count ?? endpoints.length}</b></div>
                <div><span>风险</span><b className={`stat-${riskClass === "ok" ? "ok" : "warn"}`}>{findings.length}</b></div>
                <div><span>耗时</span><b>{summary ? `${Math.round(summary.duration_ms)}ms` : "-"}</b></div>
              </div>
              <div className="result-tabs">
                <span>资产 {assets.length}</span>
                <span>开放端点 {endpoints.length}</span>
                <span>风险 {findings.length}</span>
              </div>
              <div className="probe-table-wrap">
                {findings.length > 0 && (
                  <table className="probe-table">
                    <thead><tr><th>优先级</th><th>资产/端口</th><th>风险</th><th>建议</th></tr></thead>
                    <tbody>
                      {findings.map((finding, index) => (
                        <tr key={`${finding.endpoint}-${finding.title}-${index}`}>
                          <td><span className={`status-badge ${SEVERITY_CLASS[finding.severity] || "info"}`}>
                            {SEVERITY_LABEL[finding.severity] || finding.severity}</span></td>
                          <td className="mono">{finding.endpoint} · {finding.service}</td>
                          <td><b>{finding.title}</b><div className="row-detail">{finding.evidence}</div></td>
                          <td className="row-detail">{finding.advice}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {endpoints.length > 0 && (
                  <table className="probe-table table-gap">
                    <thead><tr><th>资产</th><th>状态</th><th>端口</th><th>服务</th><th>说明</th></tr></thead>
                    <tbody>
                      {endpoints.map((endpoint) => (
                        <tr key={`endpoint-${endpoint.endpoint}`}>
                          <td className="mono">{endpoint.endpoint}</td>
                          <td><span className="status-badge ok">开放</span></td>
                          <td className="mono">{endpoint.port}</td>
                          <td>{endpoint.service}</td>
                          <td className="row-detail">{endpoint.banner || endpoint.http?.server || endpoint.detail}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {assets.length > 0 && (
                  <table className="probe-table table-gap">
                    <thead><tr><th>资产</th><th>状态</th><th>开放端口</th><th>说明</th></tr></thead>
                    <tbody>
                      {assets.map((asset) => (
                        <tr key={`asset-${asset.target}`}>
                          <td className="mono">{asset.target}</td>
                          <td><span className={`status-badge ${asset.status === "alive" ? "ok" : "warn"}`}>
                            {ASSET_STATUS_LABEL[asset.status] || asset.status}</span></td>
                          <td className="mono">{asset.open_ports?.join(", ") || "-"}</td>
                          <td className="row-detail">{asset.detail}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {!results.length && <div className="empty-note">尚未扫描。扫描只做连通性与元数据识别，不保存业务正文。</div>}
              </div>
            </section>
            <ReportPane
              reportMode={reportMode}
              offlineOutput={offlineOutput}
              aiOutput={aiOutput}
              busy={reportBusy}
              canUseAi={hasKey}
              onMode={(mode) => { setReportMode(mode); }}
              onRun={runExposureReport}
              onStop={() => reportAbort.current?.abort()}
              error={reportError}
              output={reportOutput}
              onCopy={() => navigator.clipboard?.writeText(reportOutput)}
              onDownload={() => downloadMarkdown(reportOutput, "packet-lens-exposure")}
            />
          </div>
        </div>
      )}

      {tab === "config" && (
        <div className="security-layout">
          <section className="probe-config">
            <label className="field-label" htmlFor="config-file">设备配置或日志</label>
            <input id="config-file" className="input file-input" type="file"
                   accept=".txt,.log,.cfg,.conf" onChange={(event) => setAuditFile(event.target.files?.[0] || null)} />
            <div className="counter-note">支持 .txt / .log / .cfg / .conf，上限 20MB；文件只在内存中解析。</div>
            <button className="btn btn-primary" onClick={submitAudit} disabled={!auditFile || uploading}>
              <Upload size={14} /> {uploading ? "正在解析..." : "上传并审计"}
            </button>
            {auditError && <div className="ai-error">{auditError}</div>}
            <div className="legal-note full-width">上传前建议先自行删除无需分析的业务凭据；系统会脱敏证据中的凭据类字段。</div>
          </section>

          <div className="security-results">
            <section className="panel">
              <div className="panel-head"><ShieldAlert size={16} /><h3>配置审计结果</h3></div>
              {!audit ? (
                <div className="empty-note">上传后本地识别厂商、解析常见风险配置并生成离线报告。</div>
              ) : (
                <>
                  <div className="result-stats five">
                    <div><span>厂商</span><b>{audit.vendor}</b></div>
                    <div><span>设备</span><b className="device-name">{audit.device_name}</b></div>
                    <div><span>配置行</span><b>{audit.config_line_count}</b></div>
                    <div><span>发现</span><b>{audit.finding_count}</b></div>
                    <div><span>高优先级</span><b>{(audit.summary.critical || 0) + (audit.summary.high || 0)}</b></div>
                  </div>
                  <div className="probe-table-wrap">
                    {audit.findings.length ? (
                      <table className="probe-table">
                        <thead><tr><th>级别</th><th>发现</th><th>证据（已脱敏）</th><th>建议</th></tr></thead>
                        <tbody>
                          {audit.findings.map((finding, index) => (
                            <tr key={`${finding.id}-${index}`}>
                              <td><span className={`status-badge ${SEVERITY_CLASS[finding.severity] || "info"}`}>
                                {SEVERITY_LABEL[finding.severity] || finding.severity}</span></td>
                              <td><b>{finding.title}</b><div className="row-detail">{finding.category}</div></td>
                              <td><pre className="evidence">{finding.evidence}</pre></td>
                              <td className="row-detail">{finding.advice}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : <div className="empty-note">未命中内置配置审计规则。</div>}
                  </div>
                </>
              )}
            </section>
            <section className="panel analysis-panel">
              <div className="panel-head">
                <FileSearch size={16} />
                <h3>离线报告 / AI 增强</h3>
                <div className="scope-seg report-switch">
                  <button className={auditReportMode === "offline" ? "on" : ""}
                          onClick={() => setAuditReportMode("offline")} disabled={!audit}>离线</button>
                  <button className={auditReportMode === "ai" ? "on" : ""}
                          onClick={() => setAuditReportMode("ai")} disabled={!audit}>AI</button>
                </div>
              </div>
              {auditAiBusy ? (
                <button className="btn ai-run" onClick={() => auditAbort.current?.abort()}>
                  <Square size={14} /> 停止
                </button>
              ) : (
                <button className="btn btn-primary ai-run" disabled={!audit}
                        onClick={() => {
                          if (auditReportMode === "ai") runAuditAi();
                        }}>
                  <Play size={14} /> {auditReportMode === "offline" ? "查看离线报告" : "开始 AI 解读"}
                </button>
              )}
              {auditReportMode === "ai" && !hasKey && <div className="ai-error">AI 未配置；离线报告可正常使用。</div>}
              {auditReportMode === "ai" && auditAiError && <div className="ai-error">{auditAiError}</div>}
              <div className="markdown-output analysis-output" aria-live="polite">
                {auditReportMode === "offline"
                  ? (audit ? <Markdown text={audit.report} /> : <span className="placeholder">等待审计</span>)
                  : (auditAiOutput ? <Markdown text={auditAiOutput} streaming={auditAiBusy} />
                    : <span className="placeholder">AI 解读将显示在这里</span>)}
              </div>
              <div className="ai-footer">
                <span className="stream-note">{auditReportMode === "offline" ? "本地规则生成" : "AI 增强输出"}</span>
                <span className="grow" />
                <button className="btn btn-ghost btn-icon-only" disabled={!audit}
                        onClick={() => navigator.clipboard?.writeText(
                          auditReportMode === "offline" ? audit.report : auditAiOutput,
                        )} title="复制结果" aria-label="复制结果">
                  <Copy size={15} />
                </button>
                <button className="btn btn-ghost btn-icon-only" disabled={!audit}
                        onClick={() => downloadMarkdown(
                          auditReportMode === "offline" ? audit.report : auditAiOutput,
                          "packet-lens-config-audit",
                        )} title="下载报告" aria-label="下载报告">
                  <Download size={15} />
                </button>
              </div>
            </section>
          </div>
        </div>
      )}
    </>
  );

  if (embedded) return content;
  return <main className="security-page">{content}</main>;
}
