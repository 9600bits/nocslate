import React, { useMemo, useRef, useState } from "react";
import {
  Activity, ArrowLeft, Bot, Copy, Download, Eye, History, Play, RefreshCw,
  Save, Settings2, Square, Timer, Trash2,
} from "lucide-react";
import {
  createMonitorTask, deleteMonitorTask, fetchMonitorDiff, fetchMonitorRuns,
  fetchMonitorTasks, fetchOfflineProbeReport, runMonitorTask, streamProbe,
  streamProbeAnalyze, updateMonitorTask,
} from "../api";
import Markdown from "./Markdown.jsx";

const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
  993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379,
  8080, 8443, 9090, 27017,
];

const STATUS_LABEL = {
  running: "探测中",
  reachable: "可达",
  timeout: "超时",
  unreachable: "不可达",
  error: "错误",
  ok: "正常",
  redirect: "重定向",
  client_error: "4xx",
  server_error: "5xx",
  open: "开放",
  closed: "关闭",
  refused: "拒绝",
  tls_error: "TLS 失败",
};

const STATUS_CLASS = {
  running: "warn",
  reachable: "ok",
  ok: "ok",
  redirect: "warn",
  client_error: "warn",
  server_error: "err",
  timeout: "warn",
  unreachable: "err",
  closed: "warn",
  refused: "warn",
  tls_error: "err",
  error: "err",
  open: "ok",
};

function parseTargets(text) {
  return [...new Set(
    text.split(/[\n,，;；]+/)
      .map((s) => s.trim())
      .filter((s) => s && s !== "http://" && s !== "https://"),
  )].slice(0, 512);
}

function parsePorts(text) {
  const ports = [];
  for (const part of text.split(/[\n,，;；\s]+/)) {
    const value = part.trim();
    if (!value) continue;
    if (value.includes("-")) {
      const [a, b] = value.split("-").map((n) => Number(n));
      if (Number.isInteger(a) && Number.isInteger(b) && a > 0 && b <= 65535 && a <= b) {
        for (let p = a; p <= b && ports.length < 8192; p += 1) ports.push(p);
      }
    } else {
      const n = Number(value);
      if (Number.isInteger(n) && n > 0 && n <= 65535) ports.push(n);
    }
  }
  return [...new Set(ports)].slice(0, 8192);
}

function resultKey(result, index) {
  void index;
  return resultIdentity(result);
}

function resultIdentity(result) {
  if (result.type === "ping" || result.type === "ping_update") {
    return `ping:${result.target}`;
  }
  if (result.type === "tcp") {
    return `tcp:${result.endpoint || `${result.target}:${result.port}`}`;
  }
  return `${result.type}:${result.target}`;
}

function upsertResult(list, result) {
  const identity = resultIdentity(result);
  const index = list.findIndex((item) => resultIdentity(item) === identity);
  if (index === -1) return [...list, result];
  const next = [...list];
  next[index] = result;
  return next;
}

function normalizePingCount(value) {
  const count = Number(value);
  if (!Number.isFinite(count)) return 1;
  return Math.min(65536, Math.max(1, Math.trunc(count)));
}

function runningPingResult(event) {
  return {
    ...event,
    type: "ping",
    ok: null,
    status: "running",
  };
}

function resultText(result) {
  if (result.type === "http") return result.detail || result.status;
  if (result.type === "tcp") return result.detail;
  return result.detail || result.status;
}

function resultStatus(result) {
  if (result.type === "http") return result.category || result.status;
  return result.status;
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function ProbePage({ cfg, onNavigate, onOpenConfig, embedded = false }) {
  const [probeType, setProbeType] = useState("ping");
  const [targetsText, setTargetsText] = useState("127.0.0.1\n192.168.1.1");
  const [portText, setPortText] = useState(DEFAULT_PORTS.join(", "));
  const [pingCount, setPingCount] = useState(4);
  const [pingTimeout, setPingTimeout] = useState(1000);
  const [concurrency, setConcurrency] = useState(64);
  const [tcpConcurrency, setTcpConcurrency] = useState(128);
  const [httpTimeout, setHttpTimeout] = useState(10);
  const [httpMethod, setHttpMethod] = useState("GET");
  const [followRedirects, setFollowRedirects] = useState(true);
  const [verifyTls, setVerifyTls] = useState(true);
  const [advanced, setAdvanced] = useState(false);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState([]);
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const [summary, setSummary] = useState(null);
  const [probeError, setProbeError] = useState("");
  const [aiOutput, setAiOutput] = useState("");
  const [aiError, setAiError] = useState("");
  const [aiStreaming, setAiStreaming] = useState(false);
  const [reportMode, setReportMode] = useState("offline");
  const [offlineOutput, setOfflineOutput] = useState("");
  const [offlineError, setOfflineError] = useState("");
  const [offlineBusy, setOfflineBusy] = useState(false);
  const [tasks, setTasks] = useState([]);
  const [taskName, setTaskName] = useState("");
  const [taskInterval, setTaskInterval] = useState(300);
  const [expandedTask, setExpandedTask] = useState(null);
  const [runs, setRuns] = useState([]);
  const [diff, setDiff] = useState(null);
  const [monitorBusy, setMonitorBusy] = useState(false);
  const [monitorError, setMonitorError] = useState("");
  const probeAbort = useRef(null);
  const aiAbort = useRef(null);

  const targets = useMemo(() => parseTargets(targetsText), [targetsText]);
  const ports = useMemo(() => parsePorts(portText), [portText]);
  const tcpGroups = useMemo(() => {
    const groups = new Map();
    for (const result of results) {
      if (result.type !== "tcp") continue;
      if (!groups.has(result.target)) groups.set(result.target, []);
      groups.get(result.target).push(result);
    }
    return [...groups.entries()].map(([target, items]) => ({
      target,
      items: items.sort((a, b) => (a.port || 0) - (b.port || 0)),
      open: items.filter((item) => item.status === "open").length,
    }));
  }, [results]);
  const hasKey = cfg?.has_key;

  const buildBody = () => ({
    type: probeType,
    targets,
    ping_count: normalizePingCount(pingCount),
    ping_timeout_ms: pingTimeout,
    concurrency,
    tcp_concurrency: tcpConcurrency,
    http_method: httpMethod,
    follow_redirects: followRedirects,
    verify_tls: verifyTls,
    http_timeout_s: httpTimeout,
    ports,
  });

  const run = async () => {
    if (!targets.length || running) return;
    setRunning(true);
    setResults([]);
    setSummary(null);
    setProbeError("");
    setAiOutput("");
    setAiError("");
    setOfflineOutput("");
    setOfflineError("");
    setProgress({ done: 0, total: 0 });
    const controller = new AbortController();
    probeAbort.current = controller;
    try {
      await streamProbe(buildBody(), {
        onEvent: (event) => {
          if (event.type === "start") setProgress({ done: 0, total: event.total || 0 });
          if (event.type === "ping_update") {
            setResults((prev) => upsertResult(prev, runningPingResult(event)));
          }
          if (event.type === "result") {
            setResults((prev) => upsertResult(prev, event.result));
            setProgress({ done: event.done, total: event.total });
          }
          if (event.type === "summary") setSummary(event);
          if (event.type === "error") setProbeError(event.message);
        },
        onError: (message) => setProbeError(message),
      }, controller.signal);
    } catch (err) {
      if (err?.name !== "AbortError") setProbeError(String(err.message || err));
    } finally {
      setRunning(false);
      probeAbort.current = null;
    }
  };

  const stop = () => probeAbort.current?.abort();

  const analyzeSample = useMemo(() => {
    const bad = results.filter((r) => {
      const s = resultStatus(r);
      return r.ok === false || ["timeout", "unreachable", "error", "tls_error", "server_error", "client_error"].includes(s);
    });
    const good = results.filter((r) => !bad.includes(r));
    return [...bad.slice(0, 40), ...good.slice(0, 10)];
  }, [results]);

  const runOffline = async () => {
    if (!summary || !analyzeSample.length) return;
    setOfflineOutput("");
    setOfflineError("");
    setOfflineBusy(true);
    try {
      const data = await fetchOfflineProbeReport({
        probe_type: probeType,
        summary,
        results: analyzeSample,
      });
      setOfflineOutput(data.markdown);
    } catch (err) {
      setOfflineError(String(err.message || err));
    } finally {
      setOfflineBusy(false);
    }
  };

  const runAi = async () => {
    if (!summary || !analyzeSample.length) return;
    setAiOutput("");
    setAiError("");
    setAiStreaming(true);
    const controller = new AbortController();
    aiAbort.current = controller;
    let acc = "";
    try {
      await streamProbeAnalyze({
        probe_type: probeType,
        summary,
        results: analyzeSample,
      }, {
        onEvent: (event) => {
          if (event.delta) {
            acc += event.delta;
            setAiOutput(acc);
          }
          if (event.error) setAiError((prev) => prev || event.error);
        },
        onError: (message) => setAiError((prev) => prev || message),
      }, controller.signal);
    } catch (err) {
      if (err?.name !== "AbortError") setAiError(String(err.message || err));
    } finally {
      setAiStreaming(false);
      aiAbort.current = null;
    }
  };

  const stopAi = () => aiAbort.current?.abort();

  const loadTasks = async () => {
    try {
      const data = await fetchMonitorTasks();
      setTasks(data.tasks || []);
      setMonitorError("");
    } catch (err) {
      setMonitorError(String(err.message || err));
    }
  };

  React.useEffect(() => { loadTasks(); }, []);

  const saveTask = async () => {
    if (!taskName.trim() || !targets.length) return;
    setMonitorBusy(true);
    setMonitorError("");
    try {
      await createMonitorTask({
        ...buildBody(),
        name: taskName.trim(),
        interval_seconds: Math.max(30, Math.trunc(taskInterval) || 30),
        ping_count: Math.min(100, normalizePingCount(pingCount)),
      });
      setTaskName("");
      await loadTasks();
    } catch (err) {
      setMonitorError(String(err.message || err));
    } finally {
      setMonitorBusy(false);
    }
  };

  const runTask = async (id) => {
    setMonitorBusy(true);
    setMonitorError("");
    try {
      await runMonitorTask(id);
      await loadTasks();
      if (expandedTask === id) {
        const [runData, diffData] = await Promise.all([
          fetchMonitorRuns(id), fetchMonitorDiff(id),
        ]);
        setRuns(runData.runs || []);
        setDiff(diffData);
      }
    } catch (err) {
      setMonitorError(String(err.message || err));
    } finally {
      setMonitorBusy(false);
    }
  };

  const toggleTask = async (task) => {
    setMonitorBusy(true);
    try {
      await updateMonitorTask(task.id, { enabled: !task.enabled });
      await loadTasks();
    } catch (err) {
      setMonitorError(String(err.message || err));
    } finally {
      setMonitorBusy(false);
    }
  };

  const removeTask = async (id) => {
    if (!confirm("确定删除该监控任务及其历史？")) return;
    setMonitorBusy(true);
    try {
      await deleteMonitorTask(id);
      if (expandedTask === id) setExpandedTask(null);
      await loadTasks();
    } catch (err) {
      setMonitorError(String(err.message || err));
    } finally {
      setMonitorBusy(false);
    }
  };

  const showHistory = async (id) => {
    if (expandedTask === id) {
      setExpandedTask(null);
      setRuns([]);
      setDiff(null);
      return;
    }
    setExpandedTask(id);
    setMonitorBusy(true);
    try {
      const [runData, diffData] = await Promise.all([
        fetchMonitorRuns(id), fetchMonitorDiff(id),
      ]);
      setRuns(runData.runs || []);
      setDiff(diffData);
    } catch (err) {
      setMonitorError(String(err.message || err));
    } finally {
      setMonitorBusy(false);
    }
  };
  const reportOutput = reportMode === "offline" ? offlineOutput : aiOutput;
  const reportError = reportMode === "offline" ? offlineError : aiError;
  const reportBusy = reportMode === "offline" ? offlineBusy : aiStreaming;
  const copyReport = () => navigator.clipboard?.writeText(reportOutput);
  const downloadReport = () => {
    if (!reportOutput) return;
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const blob = new Blob([reportOutput], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `packet-lens-probe-${probeType}-${stamp}.md`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const percent = progress.total ? Math.round((progress.done / progress.total) * 100) : 0;

  const content = (
    <>
      {!embedded && (
        <div className="page-head">
          <button className="btn btn-ghost" onClick={() => onNavigate("home")}>
            <ArrowLeft size={15} /> 返回首页
          </button>
          <div className="page-title">
            <Activity size={18} className="accent-lake" />
            <h2>网络探测</h2>
          </div>
          <span className="legal-note">仅用于你有权测试的网络</span>
        </div>
      )}

      <div className="probe-layout">
        <section className="probe-config">
          <div className="seg tabs" role="tablist" aria-label="探测类型">
            {["ping", "http", "tcp"].map((type) => (
              <button key={type} role="tab" aria-selected={probeType === type}
                      className={probeType === type ? "on" : ""}
                      onClick={() => setProbeType(type)}>
                {type === "ping" ? "Ping" : type === "http" ? "HTTP" : "TCP 端口"}
              </button>
            ))}
          </div>

          <label className="field-label" htmlFor="probe-targets">目标（每行一个，逗号也可）</label>
          <textarea id="probe-targets" className="input textarea" rows={6}
                    value={targetsText} onChange={(e) => setTargetsText(e.target.value)}
                    placeholder="127.0.0.1&#10;example.com&#10;192.168.1.10" />
          <div className="counter-note">{targets.length}/512 个目标</div>

          {probeType === "tcp" && (
            <>
              <label className="field-label" htmlFor="probe-ports">端口（支持 80,443 或 8000-8010）</label>
              <textarea id="probe-ports" className="input textarea ports-textarea" rows={10}
                        value={portText} onChange={(e) => setPortText(e.target.value)} />
              <div className="counter-note">{ports.length} 个端口，组合上限 8192</div>
            </>
          )}

          <button className="btn btn-ghost advanced-toggle" onClick={() => setAdvanced((v) => !v)}>
            <Settings2 size={14} /> {advanced ? "收起高级设置" : "高级设置"}
          </button>
          {advanced && (
            <div className="advanced-grid">
              <label className="compact-field">
                <span>Ping 次数</span>
                <input className="input" type="number" min="1" max="65536"
                       value={pingCount}
                       onChange={(e) => setPingCount(e.target.value === "" ? "" : Number(e.target.value))}
                       onBlur={() => setPingCount(normalizePingCount(pingCount))} />
              </label>
              <label className="compact-field">
                <span>Ping 超时 ms</span>
                <input className="input" type="number" min="100" max="10000"
                       value={pingTimeout} onChange={(e) => setPingTimeout(Number(e.target.value))} />
              </label>
              <label className="compact-field">
                <span>Ping/HTTP 并发</span>
                <input className="input" type="number" min="1" max="256"
                       value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value))} />
              </label>
              <label className="compact-field">
                <span>TCP 并发</span>
                <input className="input" type="number" min="1" max="512"
                       value={tcpConcurrency} onChange={(e) => setTcpConcurrency(Number(e.target.value))} />
              </label>
              {probeType === "http" && (
                <>
                  <label className="compact-field">
                    <span>HTTP 方法</span>
                    <select className="select" value={httpMethod}
                            onChange={(e) => setHttpMethod(e.target.value)}>
                      <option value="GET">GET</option>
                      <option value="HEAD">HEAD</option>
                    </select>
                  </label>
                  <label className="compact-field">
                    <span>HTTP 超时 s</span>
                    <input className="input" type="number" min="1" max="30"
                           value={httpTimeout} onChange={(e) => setHttpTimeout(Number(e.target.value))} />
                  </label>
                  <label className="check-field">
                    <input type="checkbox" checked={followRedirects}
                           onChange={(e) => setFollowRedirects(e.target.checked)} />
                    跟随重定向
                  </label>
                  <label className="check-field">
                    <input type="checkbox" checked={verifyTls}
                           onChange={(e) => setVerifyTls(e.target.checked)} />
                    TLS 证书校验
                  </label>
                </>
              )}
            </div>
          )}

          {running ? (
            <button className="btn probe-run stop" onClick={stop}>
              <Square size={15} /> 停止
            </button>
          ) : (
            <button className="btn btn-primary probe-run" onClick={run} disabled={!targets.length}>
              <Play size={15} /> 开始探测
            </button>
          )}
          {running && (
            <div className="progress" role="progressbar" aria-valuenow={percent} aria-valuemin="0" aria-valuemax="100">
              <div className="progress-bar" style={{ width: `${percent}%` }} />
            </div>
          )}
          {probeError && <div className="ai-error">{probeError}</div>}
        </section>

        <section className="probe-results">
          <div className="result-stats">
            <div>
              <span className="stat-value">{progress.done}</span>
              <span className="stat-label">已完成</span>
            </div>
            <div>
              <span className="stat-value accent-lake">{summary?.ok_count ?? 0}</span>
              <span className="stat-label">正常</span>
            </div>
            <div>
              <span className="stat-value accent-coral">{summary?.error_count ?? 0}</span>
              <span className="stat-label">异常</span>
            </div>
            <div>
              <span className="stat-value">{summary ? `${(summary.duration_ms / 1000).toFixed(1)}s` : "—"}</span>
              <span className="stat-label">耗时</span>
            </div>
          </div>
          {summary && (
            <div className="status-map">
              {Object.entries(summary.statuses || {}).map(([key, count]) => (
                <span key={key} className={`status-badge st-${STATUS_CLASS[key] || "warn"}`}>
                  {STATUS_LABEL[key] || key} {count}
                </span>
              ))}
            </div>
          )}

          <div className="probe-table-wrap">
            {results.length === 0 && !running && (
              <div className="probe-empty">结果将在这里逐步显示</div>
            )}
            {results.length > 0 && probeType === "tcp" && (
              <div className="tcp-groups">
                {tcpGroups.map((group) => (
                  <section key={group.target} className="tcp-group" aria-label={`目标 ${group.target} 端口结果`}>
                    <header className="tcp-group-head">
                      <span>IP:</span>
                      <span className="tcp-ip">{group.target}</span>
                      <span className="tcp-group-summary">
                        {group.open} 开放 / {group.items.length} 端口
                      </span>
                    </header>
                    <div className="tcp-port-list">
                      {group.items.map((result) => (
                        <div key={resultKey(result)} className="tcp-port-row">
                          <span className="mono-cell tcp-port">{result.port}</span>
                          <span>
                            <span className={`status-badge st-${STATUS_CLASS[resultStatus(result)] || "warn"}`}>
                              {STATUS_LABEL[resultStatus(result)] || result.status}
                            </span>
                          </span>
                          <span className="tcp-port-detail" title={resultText(result)}>{resultText(result)}</span>
                          <span className="mono-cell tcp-port-latency">
                            {`${result.elapsed_ms?.toFixed?.(0) || result.elapsed_ms} ms`}
                          </span>
                        </div>
                      ))}
                    </div>
                  </section>
                ))}
              </div>
            )}
            {results.length > 0 && probeType !== "tcp" && (
              <table className="probe-table">
                <thead>
                  <tr>
                    <th>目标</th>
                    <th>状态</th>
                    <th>{probeType === "ping" ? "平均延迟" : "耗时"}</th>
                    <th>说明</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((result, index) => (
                    <tr key={resultKey(result, index)}>
                      <td className="mono-cell">
                        {result.type === "tcp" ? result.endpoint : result.target}
                      </td>
                      <td>
                        <span className={`status-badge st-${STATUS_CLASS[resultStatus(result)] || "warn"}`}>
                          {STATUS_LABEL[resultStatus(result)] || result.status}
                        </span>
                      </td>
                      <td className="mono-cell">
                        {probeType === "ping" && result.avg_ms != null
                          ? `${result.avg_ms} ms`
                          : probeType === "ping"
                            ? "—"
                            : `${result.elapsed_ms?.toFixed?.(0) || result.elapsed_ms} ms`}
                      </td>
                      <td className="probe-detail" title={resultText(result)}>{resultText(result)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          <div className="probe-ai">
            <div className="probe-ai-head">
              <Bot size={15} className="ai-icon" />
              <span>诊断分析</span>
              <span className="grow" />
              {reportBusy ? (
                reportMode === "ai" ? (
                  <button className="btn btn-ghost btn-icon-only" onClick={stopAi} title="停止 AI" aria-label="停止 AI">
                    <Square size={14} />
                  </button>
                ) : (
                  <button className="btn btn-ghost btn-icon-only" disabled title="正在生成" aria-label="正在生成">
                    <Square size={14} />
                  </button>
                )
              ) : null}
              <button className="btn btn-ghost btn-icon-only" onClick={onOpenConfig}
                      title="AI 配置" aria-label="AI 配置">
                <Settings2 size={14} />
              </button>
            </div>
            <div className="report-mode-row">
              <div className="scope-seg" role="tablist" aria-label="探测诊断模式">
                <button className={reportMode === "offline" ? "on" : ""}
                        onClick={() => setReportMode("offline")}>离线报告</button>
                <button className={reportMode === "ai" ? "on" : ""}
                        onClick={() => setReportMode("ai")}>AI 解读</button>
              </div>
              <span className="grow" />
              <button className="btn btn-ghost btn-icon-only" onClick={copyReport}
                      disabled={!reportOutput} title="复制结果" aria-label="复制结果">
                <Copy size={14} />
              </button>
              <button className="btn btn-ghost btn-icon-only" onClick={downloadReport}
                      disabled={!reportOutput} title="下载 Markdown 报告" aria-label="下载 Markdown 报告">
                <Download size={14} />
              </button>
              {reportMode === "offline" ? (
                <button className="btn btn-primary ai-go" onClick={runOffline}
                        disabled={!summary || offlineBusy}>
                  <Play size={14} /> 本地报告
                </button>
              ) : (
                <button className="btn btn-primary ai-go" onClick={runAi}
                        disabled={!summary || aiStreaming || !hasKey}>
                  <Play size={14} /> AI 解读
                </button>
              )}
            </div>
            {reportMode === "ai" && !hasKey && (
              <div className="ai-error">尚未配置 AI API。可以先使用本地报告，联网配置后再使用 AI 解读。</div>
            )}
            {reportError && <div className="ai-error">{reportError}</div>}
            <div className="ai-output markdown-output">
              {reportOutput
                ? <Markdown text={reportOutput} streaming={reportBusy} />
                : <span className="placeholder">探测结束后可生成本地诊断报告；AI 解读为可选增强。</span>}
            </div>
          </div>
        </section>
      </div>

      <section className="monitor-panel" aria-label="定时探测监控">
        <div className="monitor-head">
          <Timer size={16} className="accent-gold" />
          <h3>定时监控</h3>
          <span className="grow" />
          <button className="btn btn-ghost" onClick={loadTasks} aria-label="刷新任务列表">
            <RefreshCw size={14} /> 刷新
          </button>
        </div>

        <div className="monitor-create">
          <input className="input" value={taskName} onChange={(e) => setTaskName(e.target.value)}
                 placeholder="任务名称，如：核心交换巡检" aria-label="监控任务名称" />
          <label className="compact-field interval-field">
            <span>间隔（秒）</span>
            <input className="input" type="number" min="30" max="86400" value={taskInterval}
                   onChange={(e) => setTaskInterval(Number(e.target.value))} />
          </label>
          <button className="btn btn-primary" onClick={saveTask}
                  disabled={monitorBusy || !taskName.trim() || !targets.length}>
            <Save size={14} /> 保存当前配置
          </button>
        </div>
        <div className="counter-note">任务会保存当前探测类型、目标、端口和高级设置；Ping 任务每次最多保存 100 次。</div>

        {monitorError && <div className="ai-error">{monitorError}</div>}
        {tasks.length === 0 ? (
          <div className="probe-empty">暂无任务。配置好目标后保存即可自动巡检。</div>
        ) : (
          <div className="monitor-table-wrap">
            <table className="monitor-table">
              <thead>
                <tr><th>任务</th><th>类型</th><th>间隔</th><th>状态</th><th>最近 / 下次</th><th></th></tr>
              </thead>
              <tbody>
                {tasks.map((task) => (
                  <React.Fragment key={task.id}>
                    <tr>
                      <td>{task.name}</td>
                      <td className="mono-cell">{task.probe_type.toUpperCase()}</td>
                      <td className="mono-cell">{task.interval_seconds}s</td>
                      <td>
                        <span className={`status-badge st-${task.enabled ? "ok" : "warn"}`}>
                          {task.enabled ? "启用" : "暂停"}
                        </span>
                      </td>
                      <td className="mono-cell">
                        {task.last_status} · {formatTime(task.last_run_at)} / {formatTime(task.next_run_at)}
                      </td>
                      <td className="monitor-actions">
                        <button className="btn btn-ghost" onClick={() => runTask(task.id)} disabled={monitorBusy}>
                          <Play size={13} /> 执行
                        </button>
                        <button className="btn btn-ghost" onClick={() => showHistory(task.id)}
                                aria-expanded={expandedTask === task.id}>
                          <History size={13} /> 历史
                        </button>
                        <button className="btn btn-ghost" onClick={() => toggleTask(task)} disabled={monitorBusy}>
                          {task.enabled ? "暂停" : "启用"}
                        </button>
                        <button className="icon-btn danger" onClick={() => removeTask(task.id)}
                                title="删除任务" aria-label={`删除任务 ${task.name}`}>
                          <Trash2 size={13} />
                        </button>
                      </td>
                    </tr>
                    {expandedTask === task.id && (
                      <tr className="history-row">
                        <td colSpan={6}>
                          {diff?.has_previous && diff.changes.length > 0 && (
                            <div className="diff-list">
                              <div className="form-label">最近两次差异</div>
                              {diff.changes.slice(0, 30).map((change, index) => (
                                <div key={index} className="diff-item">
                                  <span className="mono-cell">{change.key}</span>
                                  <span className={`status-badge ${change.kind === "opened" ? "st-ok" : change.kind === "closed" ? "st-err" : "st-warn"}`}>
                                    {change.kind === "opened" ? "新开放" : change.kind === "closed" ? "新关闭" : "状态变化"}
                                  </span>
                                  <span>{change.old?.status || change.old?.category || "无"} → {change.new?.status || change.new?.category || "无"}</span>
                                </div>
                              ))}
                            </div>
                          )}
                          <div className="run-list">
                            {runs.map((run) => (
                              <div key={run.id} className="run-item">
                                <Eye size={13} />
                                <span className="mono-cell">{formatTime(run.started_at)}</span>
                                <span className={run.error_count ? "accent-coral" : "accent-lake"}>
                                  {run.ok_count} 正常 / {run.error_count} 异常
                                </span>
                                <span>{run.trigger === "scheduled" ? "自动" : "手动"}</span>
                                <span className="mono-cell">{(run.duration_ms / 1000).toFixed(1)}s</span>
                              </div>
                            ))}
                            {runs.length === 0 && <span className="placeholder">暂无运行记录</span>}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );

  if (embedded) return content;
  return <main className="probe-page">{content}</main>;
}
