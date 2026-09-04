import React, { useEffect, useState } from "react";
import { Activity, Bot, CheckCircle2, ChevronRight, CircleAlert, Database, FileKey2, KeyRound, Network, Play, Plus, RefreshCw, Search, Server, ShieldCheck, Terminal, Trash2, Upload, X } from "lucide-react";
import { infra, streamApi } from "../api";

const TABS = [
  ["servers", "服务器巡检", Server],
  ["network", "IP / VLAN 规划", Network],
  ["diagnostics", "一键诊断", Activity],
  ["credentials", "连接与凭据", KeyRound],
  ["knowledge", "知识与 AI", Bot],
  ["events", "事件中心", CircleAlert],
];

const SECTION_TABS = {
  assets: [["servers", "服务器巡检", Server], ["credentials", "连接与凭据", KeyRound]],
  planning: [["network", "IP / VLAN 规划", Network], ["diagnostics", "一键诊断", Activity]],
  knowledge: [["knowledge", "知识与 AI", Bot]],
  infra: TABS,
};

function useAsync(loader, deps = []) {
  const [state, setState] = useState({ data: null, loading: true, error: "" });
  const reload = () => {
    setState((s) => ({ ...s, loading: true, error: "" }));
    Promise.resolve().then(loader).then((data) => setState({ data, loading: false, error: "" })).catch((err) => setState({ data: null, loading: false, error: String(err.message || err) }));
  };
  useEffect(reload, deps); // eslint-disable-line react-hooks/exhaustive-deps
  return [state, reload];
}

function Panel({ title, icon: Icon, action, children, className = "" }) {
  return <section className={`infra-panel ${className}`}><div className="infra-panel-head"><div className="infra-panel-title">{Icon && <Icon size={16} />}<h3>{title}</h3></div>{action}</div>{children}</section>;
}

function Empty({ text = "暂无数据" }) { return <div className="infra-empty">{text}</div>; }

function ServerView() {
  const [state, reload] = useAsync(() => infra.servers(), []);
  const [selected, setSelected] = useState(null);
  const [form, setForm] = useState({ name: "", host: "", os_hint: "linux", environment: "", tags: [], remark: "" });
  const [notice, setNotice] = useState("");
  const [runs, setRuns] = useState([]); const [connections, setConnections] = useState([]); const [terminal, setTerminal] = useState(null);
  useEffect(() => { if (selected?.id) { infra.connections(selected.id).then((data) => setConnections(data.connections || [])).catch(() => setConnections([])); } else setConnections([]); }, [selected]);
  const servers = state.data?.servers || [];
  const edit = (server) => { setSelected(server); setForm({ ...server, tags: server.tags || [] }); };
  const save = async (event) => { event.preventDefault(); try { await infra.saveServer({ ...form, tags: typeof form.tags === "string" ? form.tags.split(",").map((v) => v.trim()).filter(Boolean) : form.tags }, selected?.id); setNotice("服务器已保存"); setSelected(null); setForm({ name: "", host: "", os_hint: "linux", environment: "", tags: [], remark: "" }); reload(); } catch (err) { setNotice(err.message); } };
  const inspect = async (server) => { setNotice(`正在创建 ${server.name} 的巡检任务...`); try { const job = await infra.runInspection({ server_id: server.id }); setNotice(`任务 ${job.id} 已开始`); setTimeout(async () => { const result = await infra.inspections(server.id); setRuns(result.runs || []); }, 800); } catch (err) { setNotice(err.message); } };
  const openTerminal = async (connection) => { try { const ticket = await infra.sshTicket(connection.id); setTerminal({ connection, ticket: ticket.ticket }); } catch (err) { setNotice(err.message); } };
  const serverList = state.loading ? <Empty text="载入服务器清单…" /> : state.error ? <Empty text={state.error} /> : servers.length === 0 ? <Empty text="还没有登记服务器" /> : (
    <div className="infra-list">
      {servers.map((server) => (
        <button key={server.id} className={`infra-list-row ${selected?.id === server.id ? "active" : ""}`} onClick={() => edit(server)}>
          <span className="status-dot on" /><span className="infra-grow"><b>{server.name}</b><small>{server.host} · {server.environment || "未分类"}</small></span><span className="status-pill">{server.last_inspection?.status || "未巡检"}</span><ChevronRight size={15} />
        </button>
      ))}
    </div>
  );
  const history = runs.length ? runs.map((run) => (
    <div className="infra-list-row static" key={run.id}><span className={`status-dot ${run.status === "succeeded" ? "on" : "warn"}`} /><span className="infra-grow"><b>#{run.id} · {run.summary || "巡检完成"}</b><small>{run.started_at}</small></span><span className="status-pill">{run.status}</span></div>
  )) : <Empty text={selected?.id ? "选择执行巡检后查看结果" : "选择服务器查看历史"} />;
  const drawerOpen = Boolean(selected || Object.values(form).some(Boolean));
  return <div className="infra-content">
    <div className="infra-toolbar"><div><div className="eyebrow">READ-ONLY AUTOMATION</div><h2>服务器巡检中心</h2><p>固定白名单采集基础、存储、网络、服务和安全快照。</p></div><button className="btn btn-primary" onClick={() => { setSelected({}); setForm({ name: "", host: "", os_hint: "linux", environment: "", tags: [], remark: "" }); }}><Plus size={15} />登记服务器</button></div>
    {notice && <div className="infra-notice"><CircleAlert size={15} />{notice}<button className="btn btn-icon-only btn-ghost" onClick={() => setNotice("")}><X size={14} /></button></div>}
    <div className="infra-grid infra-grid-2">
      <Panel title={`已登记服务器 · ${servers.length}`} icon={Server} action={<button className="btn btn-ghost btn-icon-only" onClick={reload} title="刷新"><RefreshCw size={15} /></button>}>{serverList}</Panel>
      <Panel title="连接与巡检历史" icon={Database}><div className="infra-list">{connections.map((connection) => <div className="infra-list-row static" key={`c-${connection.id}`}><Terminal size={15} /><span className="infra-grow"><b>{connection.protocol.toUpperCase()} · {connection.username || "未配置用户"}</b><small>{connection.host}:{connection.port}</small></span><button className="btn btn-ghost" onClick={() => connection.protocol === "ssh" ? openTerminal(connection) : infra.launchConnection(connection.id)}>{connection.protocol === "ssh" ? "终端" : "启动 RDP"}</button><button className="btn btn-icon-only btn-ghost" title="测试" onClick={async () => { const result = await infra.testConnection(connection.id); setNotice(result.message || (result.ok ? "连接正常" : "连接失败")); }}><Activity size={14} /></button></div>)}{history}</div></Panel>
    </div>
    {drawerOpen && <div className="infra-drawer"><div className="infra-drawer-head"><h3>{selected?.id ? "编辑服务器" : "登记服务器"}</h3><button className="btn btn-icon-only btn-ghost" onClick={() => setSelected(null)}><X size={15} /></button></div><form onSubmit={save} className="infra-form"><label>名称<input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label><label>主机名或 IP<input required value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} /></label><div className="form-row"><label>系统<select value={form.os_hint} onChange={(e) => setForm({ ...form, os_hint: e.target.value })}><option value="linux">Linux</option><option value="windows">Windows</option><option value="unknown">未知</option></select></label><label>环境<input value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })} placeholder="生产 / 测试" /></label></div><label>标签<input value={Array.isArray(form.tags) ? form.tags.join(",") : form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="数据库, 核心" /></label><label>备注<textarea rows="3" value={form.remark} onChange={(e) => setForm({ ...form, remark: e.target.value })} /></label><div className="infra-form-actions"><button type="button" className="btn" onClick={() => selected?.id && inspect(selected)} disabled={!selected?.id}><Play size={14} />执行巡检</button><button className="btn btn-primary" type="submit">保存</button></div></form></div>}
    {terminal && <TerminalModal terminal={terminal} onClose={() => setTerminal(null)} />}
  </div>;
}

function TerminalModal({ terminal, onClose }) {
  const [output, setOutput] = useState("正在连接 SSH…\n"); const [input, setInput] = useState("");
  useEffect(() => { const scheme = window.location.protocol === "https:" ? "wss" : "ws"; const socket = new WebSocket(`${scheme}://${window.location.host}/ws/ssh/${terminal.ticket}`); window.__nocslateSocket = socket; socket.onmessage = (event) => { try { const value = JSON.parse(event.data); if (value.type === "output") setOutput((old) => old + value.data); if (value.type === "error") setOutput((old) => `${old}\n[错误] ${value.message}\n`); } catch { /* ignore */ } }; socket.onclose = () => setOutput((old) => `${old}\n[连接已关闭]\n`); return () => { if (window.__nocslateSocket === socket) delete window.__nocslateSocket; socket.close(); }; }, [terminal.ticket]);
  const send = (event) => { event.preventDefault(); const el = event.currentTarget.elements.command; if (!el.value) return; window.__nocslateSocket?.send(JSON.stringify({ type: "input", data: `${el.value}\n` })); setInput(""); };
  return <div className="terminal-mask"><div className="terminal-modal"><div className="infra-drawer-head"><div><h3>SSH · {terminal.connection.host}</h3><small>终端正文仅保存在当前窗口内</small></div><button className="btn btn-icon-only btn-ghost" onClick={onClose}><X size={15} /></button></div><pre className="terminal-output">{output}</pre><form className="terminal-input" onSubmit={send}><span>$</span><input name="command" autoFocus value={input} onChange={(e) => setInput(e.target.value)} placeholder="输入命令后回车" /></form></div></div>;
}

function DiagnosticsView() {
  const [target, setTarget] = useState(""); const [state, reload] = useAsync(() => infra.diagnostics(), []); const [notice, setNotice] = useState("");
  const runs = state.data?.runs || [];
  const run = async (event) => { event.preventDefault(); if (!target.trim()) return; try { const plan = await infra.createPlan({ target: target.trim(), target_type: "temporary", options: { include_logs: false } }); const job = await infra.runPlan(plan.id); setNotice(`诊断任务 ${job.id} 已开始，后续步骤独立执行`); setTimeout(reload, 1200); } catch (err) { setNotice(err.message); } };
  return <div className="infra-content"><div className="infra-toolbar"><div><div className="eyebrow">DIAGNOSTIC PLAN</div><h2>一键故障诊断</h2><p>先生成目标与数据范围，再确认执行 DNS、Ping、路由、TCP、TLS 和 HTTP 检查。</p></div></div><Panel title="创建诊断计划" icon={Activity}><form className="diagnostic-form" onSubmit={run}><input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="域名、IP、URL 或 host:port" /><button className="btn btn-primary" type="submit"><Play size={15} />生成并执行</button></form>{notice && <div className="infra-notice"><CheckCircle2 size={15} />{notice}</div>}</Panel><Panel title="历史诊断" icon={Database} action={<button className="btn btn-ghost btn-icon-only" onClick={reload}><RefreshCw size={15} /></button>}>{runs.length ? <div className="timeline-list">{runs.map((run) => <div className="timeline-row" key={run.id}><span className={`timeline-dot ${run.status}`} /><div className="infra-grow"><b>{run.target}</b><small>{run.started_at} · {run.summary || "等待结果"}</small></div><span className="status-pill">{run.status}</span></div>)}</div> : <Empty text={state.loading ? "载入历史…" : "还没有诊断记录"} />}</Panel></div>;
}

function EventsView() {
  const [state, reload] = useAsync(() => infra.events(), []);
  const events = state.data?.events || [];
  const acknowledge = async (id) => { try { await infra.ackEvent(id); reload(); } catch { /* refresh will show current state */ } };
  return <div className="infra-content"><div className="infra-toolbar"><div><div className="eyebrow">EVENT CENTER</div><h2>事件中心</h2><p>集中查看探测、安全审计、巡检和诊断产生的异常。</p></div><button className="btn btn-ghost btn-icon-only" onClick={reload} title="刷新"><RefreshCw size={15} /></button></div><Panel title={`待处理事件 · ${events.length}`} icon={CircleAlert}>{events.length ? <div className="infra-list">{events.map((event) => <div className="infra-list-row static" key={event.id}><span className={`status-dot ${event.severity === "error" ? "warn" : "on"}`} /><span className="infra-grow"><b>{event.title}</b><small>{event.source_type} · {event.created_at} · {event.detail}</small></span><button className="btn btn-ghost" onClick={() => acknowledge(event.id)}>确认</button></div>)}</div> : <Empty text={state.loading ? "载入事件…" : "暂无待处理事件"} />}</Panel></div>;
}

const emptyRequirement = () => ({ name: "", vlan: "", hosts: "", prefix: "auto", purpose: "" });

function NetworkView() {
  const [state, reload] = useAsync(() => infra.networkPlans(), []);
  const [baseCidr, setBaseCidr] = useState("10.0.0.0/16");
  const [name, setName] = useState("办公网络规划");
  const [notes, setNotes] = useState("");
  const [requirements, setRequirements] = useState([{ ...emptyRequirement(), name: "办公终端", vlan: "10", hosts: "500" }, { ...emptyRequirement(), name: "服务器", vlan: "20", hosts: "120" }]);
  const [result, setResult] = useState(null); const [notice, setNotice] = useState(""); const [preview, setPreview] = useState(null); const [aiOutput, setAiOutput] = useState(""); const [aiBusy, setAiBusy] = useState(false); const [aiPrompt, setAiPrompt] = useState(""); const [maskPrivateIps, setMaskPrivateIps] = useState(true); const [draftPreview, setDraftPreview] = useState(null); const [draftBusy, setDraftBusy] = useState(false); const [busy, setBusy] = useState(false);
  const update = (index, key, value) => setRequirements((items) => items.map((item, i) => i === index ? { ...item, [key]: value } : item));
  const save = async (event) => {
    event.preventDefault(); setBusy(true); setNotice("");
    try { const saved = await infra.saveNetworkPlan({ name, base_cidr: baseCidr, requirements, notes }); setResult(saved.result); setNotice("规划已保存"); reload(); }
    catch (err) { setNotice(err.message); } finally { setBusy(false); }
  };
  const aiReview = async (plan) => { try { setAiOutput(""); setPreview(await infra.networkAiPreview(plan.id, {})); } catch (err) { setNotice(err.message); } };
  const previewDraft = async () => { if (!aiPrompt.trim() || draftBusy) return; setDraftBusy(true); setNotice(""); try { setDraftPreview(await infra.networkAiDraftPreview({ prompt: aiPrompt, base_cidr: baseCidr, mask_private_ips: maskPrivateIps })); } catch (err) { setNotice(err.message); } finally { setDraftBusy(false); } };
  const confirmDraft = async () => { if (!draftPreview || draftBusy) return; setDraftBusy(true); try { const draft = await infra.networkAiDraftConfirm({ preview_id: draftPreview.preview_id, confirmed: true }); setName(draft.name); setBaseCidr(draft.base_cidr); setRequirements(draft.requirements); setNotes(draft.notes || ""); setResult(draft.result); setDraftPreview(null); setNotice("AI 草案已通过本地校验，请确认后保存"); } catch (err) { setNotice(err.message); } finally { setDraftBusy(false); } };
  const confirmAi = async () => { if (!preview || aiBusy) return; setAiBusy(true); setAiOutput(""); try { await streamApi("/api/assistant/conversations/messages", { method: "POST", json: { preview_id: preview.preview_id, confirmed: true } }, (event) => { if (event.delta) setAiOutput((old) => old + event.delta); if (event.error) setNotice(event.error); }); } catch (err) { setNotice(err.message); } finally { setAiBusy(false); } };
  const plans = state.data?.plans || [];
  return <div className="infra-content network-view">
    <div className="infra-toolbar"><div><div className="eyebrow">ADDRESS SPACE DESIGN</div><h2>IP / VLAN 规划</h2><p>按主机数量自动进行 VLSM 划分，支持 /8 至 /30 掩码、VLAN 用途和网关规划。</p></div></div>
    {notice && <div className="infra-notice"><CircleAlert size={15} />{notice}<button className="btn btn-icon-only btn-ghost" onClick={() => setNotice("")}><X size={14} /></button></div>}
    <div className="infra-grid infra-grid-2">
      <Panel title="规划输入" icon={Network}><form className="infra-form" onSubmit={save}>
        <div className="network-ai-box"><div className="network-ai-title"><Bot size={15} /><span>AI 生成规划草案</span><small>生成后仍由本地计算器校验</small></div><textarea rows="3" value={aiPrompt} onChange={(e) => setAiPrompt(e.target.value)} placeholder="例如：办公区 500 台、服务器区 120 台、访客网络 200 台，分别隔离并预留 20% 扩容空间" /><label className="network-privacy-toggle"><input type="checkbox" checked={!maskPrivateIps} onChange={(e) => setMaskPrivateIps(!e.target.checked)} />允许云端 AI 使用私有网段和内网地址</label><button type="button" className="btn" onClick={previewDraft} disabled={!aiPrompt.trim() || draftBusy}><Bot size={14} />{draftBusy ? "准备中…" : "生成 AI 草案"}</button></div>
        <div className="form-row"><label>规划名称<input required value={name} onChange={(e) => setName(e.target.value)} /></label><label>基础网段<input required className="mono-input" value={baseCidr} onChange={(e) => setBaseCidr(e.target.value)} placeholder="10.0.0.0/16" /></label></div>
        <div className="network-requirements-head"><span>VLAN 需求</span><button type="button" className="btn btn-ghost" onClick={() => setRequirements((items) => [...items, emptyRequirement()])}><Plus size={14} />添加一行</button></div>
        <div className="network-requirements">{requirements.map((item, index) => <div className="network-requirement" key={index}><input aria-label="VLAN 名称" placeholder="名称" value={item.name} onChange={(e) => update(index, "name", e.target.value)} /><input aria-label="VLAN ID" className="mono-input" type="number" min="1" max="4094" placeholder="VLAN" value={item.vlan} onChange={(e) => update(index, "vlan", e.target.value)} /><input aria-label="主机数量" className="mono-input" type="number" min="1" placeholder="主机数" value={item.hosts} onChange={(e) => update(index, "hosts", e.target.value)} /><select aria-label="掩码" value={item.prefix} onChange={(e) => update(index, "prefix", e.target.value)}><option value="auto">自动掩码</option>{Array.from({ length: 23 }, (_, i) => 30 - i).map((prefix) => <option key={prefix} value={prefix}>/{prefix}</option>)}</select><input aria-label="用途" placeholder="用途（可选）" value={item.purpose} onChange={(e) => update(index, "purpose", e.target.value)} /><button type="button" className="btn btn-icon-only btn-ghost" title="删除该行" disabled={requirements.length <= 1} onClick={() => setRequirements((items) => items.filter((_, i) => i !== index))}><Trash2 size={14} /></button></div>)}</div>
        <label>备注<textarea rows="2" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="网关约定、保留地址、跨区域说明" /></label><div className="infra-form-actions"><button className="btn btn-primary" type="submit" disabled={busy}><Play size={14} />{busy ? "计算中…" : "计算并保存"}</button></div>
      </form></Panel>
      <Panel title="已保存规划" icon={Database} action={<button className="btn btn-ghost btn-icon-only" onClick={reload} title="刷新"><RefreshCw size={15} /></button>}>{plans.length ? <div className="infra-list">{plans.map((plan) => <div className="infra-list-row static" key={plan.id}><Network size={15} /><span className="infra-grow"><b>{plan.name}</b><small>{plan.base_cidr} · {plan.result?.subnets?.length || 0} 个 VLAN · {plan.updated_at}</small></span><button className="btn btn-ghost" onClick={() => { setName(plan.name); setBaseCidr(plan.base_cidr); setRequirements(plan.requirements); setNotes(plan.notes || ""); setResult(plan.result); }}>载入</button><button className="btn btn-icon-only btn-ghost" title="AI 审核" onClick={() => aiReview(plan)}><Bot size={14} /></button></div>)}</div> : <Empty text={state.loading ? "载入规划…" : "还没有保存规划"} />}</Panel>
    </div>
    {result && <Panel title={`规划结果 · ${result.base_cidr}`} icon={CheckCircle2} className="network-result"><div className="network-summary"><span>基础可用 <b>{result.base_hosts?.toLocaleString()}</b></span><span>已分配 <b>{result.allocated_addresses?.toLocaleString()}</b></span><span>剩余地址 <b>{result.free_addresses?.toLocaleString()}</b></span></div><div className="network-table-wrap"><table className="network-table"><thead><tr><th>VLAN</th><th>名称 / 用途</th><th>网段</th><th>网关</th><th>可用主机</th><th>利用率</th></tr></thead><tbody>{(result.subnets || []).map((item) => <tr key={item.vlan}><td className="mono-cell">{item.vlan}</td><td><b>{item.name}</b><small>{item.purpose || "未填写用途"}</small></td><td className="mono-cell">{item.cidr}</td><td className="mono-cell">{item.gateway}</td><td>{item.first_usable} - {item.last_usable}<small>{item.usable_hosts?.toLocaleString()} 可用</small></td><td><div className="network-util"><i style={{ width: `${Math.min(100, item.utilization_percent)}%` }} /></div><small>{item.utilization_percent}%</small></td></tr>)}</tbody></table></div></Panel>}
    {draftPreview && <div className="infra-drawer wide"><div className="infra-drawer-head"><div><h3>确认 AI 规划草案</h3><small>{draftPreview.provider?.name} · {draftPreview.requires_cloud_confirmation ? "云端请求需要确认" : "本地 Ollama"}</small></div><button className="btn btn-icon-only btn-ghost" onClick={() => setDraftPreview(null)}><X size={15} /></button></div><div className="preview-box">{draftPreview.context_preview}</div><div className="infra-form-actions"><button className="btn" onClick={() => setDraftPreview(null)}>取消</button><button className="btn btn-primary" onClick={confirmDraft} disabled={draftBusy}><Bot size={14} />{draftBusy ? "生成中…" : "确认并校验"}</button></div></div>}
    {preview && <div className="infra-drawer wide"><div className="infra-drawer-head"><div><h3>AI 规划审核</h3><small>{preview.provider?.name} · {preview.requires_cloud_confirmation ? "云端请求需要确认" : "本地 Ollama"}</small></div><button className="btn btn-icon-only btn-ghost" onClick={() => setPreview(null)}><X size={15} /></button></div><div className="preview-box">{preview.context_preview || "没有可供审核的规划数据"}</div>{aiOutput && <div className="ai-review-output"><div className="eyebrow">AI REVIEW</div><pre>{aiOutput}</pre></div>}<div className="infra-form-actions"><button className="btn" onClick={() => setPreview(null)}>关闭</button><button className="btn btn-primary" onClick={confirmAi} disabled={aiBusy}><Bot size={14} />{aiBusy ? "分析中…" : "确认并分析"}</button></div></div>}
  </div>;
}

function CredentialsView() {
  const [state, reload] = useAsync(() => infra.credentials(), []); const [form, setForm] = useState({ name: "", kind: "password", secret: "" }); const [notice, setNotice] = useState("");
  const save = async (e) => { e.preventDefault(); try { await infra.saveCredential(form); setForm({ name: "", kind: "password", secret: "" }); setNotice("凭据已使用 Windows DPAPI 加密保存"); reload(); } catch (err) { setNotice(err.message); } };
  const remove = async (id) => { if (!window.confirm("确认删除该凭据？")) return; await infra.deleteCredential(id); reload(); };
  return <div className="infra-content"><div className="infra-toolbar"><div><div className="eyebrow">LOCAL VAULT</div><h2>连接与凭据</h2><p>API 只返回元数据和掩码。SSH 私钥、密码与 Token 不会在页面回显。</p></div></div><div className="infra-grid infra-grid-2"><Panel title="已保存凭据" icon={FileKey2}>{state.data?.credentials?.length ? <div className="infra-list">{state.data.credentials.map((item) => <div className="infra-list-row static" key={item.id}><KeyRound size={15} /><span className="infra-grow"><b>{item.name}</b><small>{item.kind} · 更新于 {item.updated_at}</small></span><span className="secret-mask">••••••</span><button className="btn btn-icon-only btn-ghost" onClick={() => remove(item.id)} title="删除"><Trash2 size={14} /></button></div>)}</div> : <Empty text={state.loading ? "载入凭据…" : "还没有保存凭据"} />}</Panel><Panel title="新增凭据" icon={Plus}><form className="infra-form" onSubmit={save}><label>名称<input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label><label>类型<select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}><option value="password">SSH / RDP 密码</option><option value="private_key">SSH 私钥</option><option value="passphrase">私钥口令</option><option value="api_key">AI Key</option></select></label><label>秘密内容<textarea required rows="6" value={form.secret} onChange={(e) => setForm({ ...form, secret: e.target.value })} /></label><button className="btn btn-primary" type="submit"><KeyRound size={14} />加密保存</button>{notice && <div className="infra-notice"><CheckCircle2 size={15} />{notice}</div>}</form></Panel></div></div>;
}

function KnowledgeView() {
  const [state, reload] = useAsync(() => infra.documents(), []); const [query, setQuery] = useState(""); const [results, setResults] = useState([]); const [preview, setPreview] = useState(null); const [notice, setNotice] = useState("");
  const upload = async (e) => { const file = e.target.files?.[0]; if (!file) return; try { const doc = await infra.uploadDocument(file); setNotice(doc.duplicate ? "文档已存在，跳过重复索引" : "文档已导入并完成全文索引"); reload(); } catch (err) { setNotice(err.message); } e.target.value = ""; };
  const search = async (e) => { e.preventDefault(); if (!query.trim()) return; try { const data = await infra.searchKnowledge(query); setResults(data.results || []); } catch (err) { setNotice(err.message); } };
  const context = async () => { try { setPreview(await infra.contextPreview({ query, mask_private_ips: true })); } catch (err) { setNotice(err.message); } };
  return <div className="infra-content"><div className="infra-toolbar"><div><div className="eyebrow">LOCAL KNOWLEDGE + AI</div><h2>知识与 AI</h2><p>导入运行手册、配置和脱敏摘要；云端发送前展示实际来源与片段。</p></div><label className="btn btn-primary"><Upload size={15} />导入文档<input hidden type="file" accept=".md,.txt,.log,.yaml,.yml,.json,.pdf" onChange={upload} /></label></div>{notice && <div className="infra-notice"><CircleAlert size={15} />{notice}</div>}<div className="infra-grid infra-grid-2"><Panel title={`文档库 · ${(state.data?.documents || []).length}`} icon={Database}>{state.data?.documents?.length ? <div className="infra-list">{state.data.documents.map((doc) => <div className="infra-list-row static" key={doc.id}><FileKey2 size={15} /><span className="infra-grow"><b>{doc.title}</b><small>{doc.chunk_count} 个分块 · {doc.updated_at}</small></span></div>)}</div> : <Empty text={state.loading ? "载入文档…" : "导入第一份文档"} />}</Panel><Panel title="全文检索与上下文预览" icon={Search}><form className="diagnostic-form" onSubmit={search}><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="搜索巡检、运行手册或配置" /><button className="btn" type="submit"><Search size={14} />检索</button><button className="btn btn-primary" type="button" onClick={context} disabled={!query.trim()}><Bot size={14} />预览 AI 上下文</button></form><div className="knowledge-results">{results.map((item) => <article key={item.id}><b>{item.title}</b><p>{item.content}</p><small>来源：{item.source_type} · {item.updated_at}</small></article>)}{!results.length && <Empty text="输入关键词开始检索" />}</div></Panel></div>{preview && <div className="infra-drawer wide"><div className="infra-drawer-head"><div><h3>发送前确认</h3><small>{preview.provider?.name} · {preview.requires_cloud_confirmation ? "云端请求需要确认" : "本地 Ollama"}</small></div><button className="btn btn-icon-only btn-ghost" onClick={() => setPreview(null)}><X size={15} /></button></div><div className="preview-box">{preview.context_preview || "没有检索到相关片段"}</div><div className="infra-form-actions"><button className="btn" onClick={() => setPreview(null)}>取消</button><button className="btn btn-primary" onClick={() => setNotice("上下文已确认，可在后续对话中发送")}>确认上下文</button></div></div>}</div>;
}

export default function InfraWorkspace({ route = "servers", section = "infra", embedded = false }) {
  const tabs = SECTION_TABS[section] || TABS;
  const fallback = tabs[0]?.[0] || "servers";
  const active = tabs.some(([id]) => id === route) ? route : fallback;
  const View = { servers: ServerView, network: NetworkView, diagnostics: DiagnosticsView, credentials: CredentialsView, knowledge: KnowledgeView, events: EventsView }[active];
  if (embedded) return <View />;
  return <main className="infra-page"><aside className="infra-sidebar"><div className="infra-side-label">基础设施</div>{tabs.map(([id, label, Icon]) => <a key={id} className={active === id ? "infra-tab active" : "infra-tab"} href={`#/infra/${id}`}><Icon size={16} /><span>{label}</span>{active === id && <ChevronRight size={14} />}</a>)}<div className="infra-side-foot"><ShieldCheck size={14} /> 本机 · 只读自动化</div></aside><View /></main>;
}
