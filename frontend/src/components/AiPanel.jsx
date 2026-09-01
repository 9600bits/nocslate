import React, { useMemo, useRef, useState } from "react";
import { Bot, Copy, Download, FileSearch, Play, Settings2, Square } from "lucide-react";
import { fetchOfflineReport, streamAnalyze } from "../api";
import Markdown from "./Markdown.jsx";

export default function AiPanel({ session, cfg, selection, lastFlow, onOpenConfig }) {
  const [mode, setMode] = useState("offline");
  const [scope, setScope] = useState("overview");
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [generatedBy, setGeneratedBy] = useState("");
  const abortRef = useRef(null);

  const hasKey = cfg?.has_key;
  const busy = mode === "offline" ? generating : streaming;
  const canRun = !busy
    && (scope !== "packets" || selection.length > 0)
    && (scope !== "flow" || lastFlow);

  const contextHint = useMemo(() => {
    if (scope === "overview") return `分析整个会话：${session.filename}（${session.packet_count} 包）`;
    if (scope === "packets") {
      return selection.length
        ? `分析选中的 ${selection.length} 个报文：#${selection.slice(0, 8).join(", #")}${selection.length > 8 ? " …" : ""}`
        : "在报文列表中勾选要分析的报文";
    }
    return lastFlow ? `分析当前流：${lastFlow}` : "点击任一报文以确定要分析的流";
  }, [scope, selection, lastFlow, session]);

  const changeMode = (next) => {
    if (mode === next) return;
    setMode(next);
    setOutput("");
    setError("");
    setGeneratedBy("");
  };

  const runOffline = async () => {
    setOutput("");
    setError("");
    setGeneratedBy("");
    setGenerating(true);
    const body = { session_id: session.session_id, scope };
    if (scope === "packets") body.packet_nos = selection;
    if (scope === "flow") body.flow_key = lastFlow;
    try {
      const data = await fetchOfflineReport(body);
      setOutput(data.markdown);
      setGeneratedBy(data.generated_by || "local-rules");
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setGenerating(false);
    }
  };

  const runAi = async () => {
    setOutput("");
    setError("");
    setGeneratedBy("");
    setStreaming(true);
    const body = { session_id: session.session_id, scope };
    if (scope === "packets") body.packet_nos = selection;
    if (scope === "flow") body.flow_key = lastFlow;
    const controller = new AbortController();
    abortRef.current = controller;
    let accumulated = "";
    try {
      await streamAnalyze(body, {
        onEvent: (event) => {
          if (event.delta) {
            accumulated += event.delta;
            setOutput(accumulated);
          }
          if (event.error) setError((prev) => prev || event.error);
        },
        onError: (message) => setError((prev) => prev || message),
      }, controller.signal);
    } catch (err) {
      if (err?.name !== "AbortError") setError(String(err.message || err));
    } finally {
      setStreaming(false);
      abortRef.current = null;
    }
  };

  const run = mode === "offline" ? runOffline : runAi;
  const stop = () => abortRef.current?.abort();
  const copy = () => navigator.clipboard?.writeText(output);
  const download = () => {
    if (!output) return;
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const blob = new Blob([output], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `packet-lens-report-${stamp}.md`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <aside className="ai-pane">
      <div className="ai-head">
        {mode === "offline" ? (
          <>
            <FileSearch size={17} className="ai-icon" />
            <span className="ai-title">诊断分析</span>
            <span className="ai-config-hint ok">离线可用</span>
          </>
        ) : (
          <>
            <Bot size={17} className="ai-icon" />
            <span className="ai-title">诊断分析</span>
            <span className={`ai-config-hint ${hasKey ? "ok" : "no-key"}`}>
              {hasKey ? "AI 已连接" : "AI 未配置"}
            </span>
          </>
        )}
        <button className="btn btn-ghost btn-icon-only" onClick={onOpenConfig}
                title="AI 接口配置" aria-label="AI 接口配置">
          <Settings2 size={16} />
        </button>
      </div>
      <div className="ai-body">
        <div className="scope-row">
          <div className="scope-seg" role="tablist" aria-label="诊断模式">
            <button className={mode === "offline" ? "on" : ""}
                    onClick={() => changeMode("offline")}>离线报告</button>
            <button className={mode === "ai" ? "on" : ""}
                    onClick={() => changeMode("ai")}>AI 增强</button>
          </div>
          <div className="scope-seg" role="tablist" aria-label="分析范围">
            <button className={scope === "overview" ? "on" : ""} onClick={() => setScope("overview")}>整体概览</button>
            <button className={scope === "packets" ? "on" : ""} onClick={() => setScope("packets")}
                    disabled={selection.length === 0}>选中报文</button>
            <button className={scope === "flow" ? "on" : ""} onClick={() => setScope("flow")}
                    disabled={!lastFlow}>单条流</button>
          </div>
        </div>
        <div className="scope-context" title={contextHint}>{contextHint}</div>
        {busy
          ? (
            mode === "ai"
              ? <button className="btn ai-run" onClick={stop}><Square size={14} /> 停止</button>
              : <button className="btn ai-run" disabled><Square size={14} /> 正在生成</button>
          )
          : (
            <button className="btn btn-primary ai-run" onClick={run} disabled={!canRun}>
              <Play size={14} /> {mode === "offline" ? "生成本地报告" : "开始 AI 解读"}
            </button>
          )}
        {mode === "ai" && !hasKey && (
          <div className="ai-error">
            尚未配置 AI API。你可以先使用离线报告，联网后再使用 AI 增强解读。
          </div>
        )}
        {error && <div className="ai-error">{error}</div>}
        <div className="ai-output markdown-output" aria-live="polite">
          {output
            ? <Markdown text={output} streaming={streaming} />
            : <span className="placeholder">分析结果将显示在这里</span>}
        </div>
        <div className="ai-footer">
          <span className="stream-note">
            {busy ? (mode === "ai" ? "AI 正在输出…" : "正在生成本地报告…")
              : mode === "offline" || generatedBy === "local-rules"
                ? "本地规则生成，不需要网络"
                : "AI 增强输出"}
          </span>
          <span className="grow" />
          <button className="btn btn-ghost btn-icon-only" onClick={copy}
                  disabled={!output} title="复制结果" aria-label="复制结果">
            <Copy size={15} />
          </button>
          <button className="btn btn-ghost btn-icon-only" onClick={download}
                  disabled={!output} title="下载 Markdown 报告" aria-label="下载 Markdown 报告">
            <Download size={15} />
          </button>
        </div>
      </div>
    </aside>
  );
}
