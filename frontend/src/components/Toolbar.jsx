import React, { useRef } from "react";
import { FileText, Filter, Upload, RotateCcw, AlertTriangle, ShieldAlert } from "lucide-react";

export default function Toolbar({ session, rules, filters, onFilters, onFile, uploading, onReset, totalHits, errorCount }) {
  const fileRef = useRef(null);

  return (
    <div className="toolbar">
      <span className="file-chip">
        <FileText size={15} />
        <span title={session.filename}>{session.filename}</span>
      </span>
      <button className="btn btn-ghost btn-icon-only" title="上传新文件"
              onClick={() => fileRef.current?.click()} disabled={uploading} aria-label="上传新文件">
        <Upload size={16} />
      </button>
      <button className="btn btn-ghost btn-icon-only" title="清空会话"
              onClick={onReset} aria-label="清空会话">
        <RotateCcw size={16} />
      </button>
      <span className="toolbar-spacer" />
      <div className="stat-pairs">
        {errorCount > 0 && (
          <span className="stat-err"><ShieldAlert size={13} style={{ verticalAlign: -2, marginRight: 3 }} /><b>{errorCount}</b> 严重</span>
        )}
        {totalHits - errorCount > 0 && (
          <span className="stat-warn"><AlertTriangle size={13} style={{ verticalAlign: -2, marginRight: 3 }} /><b>{totalHits - errorCount}</b> 警告</span>
        )}
        <span><b>{session.packet_count}</b> 包</span>
      </div>
      <span className="toolbar-spacer" />
      <Filter size={14} style={{ color: "var(--fg-faint)" }} />
      <select className="select" value={filters.proto}
              onChange={(e) => onFilters({ ...filters, proto: e.target.value })} aria-label="协议过滤">
        <option value="">全部协议</option>
        <option value="TCP">TCP</option>
        <option value="UDP">UDP</option>
        <option value="ICMP">ICMP</option>
        <option value="ARP">ARP</option>
      </select>
      <select className="select" value={filters.rule}
              onChange={(e) => onFilters({ ...filters, rule: e.target.value })} aria-label="规则过滤">
        <option value="">全部规则</option>
        {rules.map((r) => (
          <option key={r.id} value={r.id}>{r.name}</option>
        ))}
      </select>
      <input className="input" style={{ width: 180 }} placeholder="搜索 IP / 端口 / 信息…"
             value={filters.q}
             onChange={(e) => onFilters({ ...filters, q: e.target.value })}
             aria-label="搜索报文" />
      <label style={{ display: "inline-flex", alignItems: "center", gap: 5, fontSize: 12, color: "var(--fg-dim)" }}>
        <input type="checkbox" checked={filters.hits_only} style={{ accentColor: "var(--iris)" }}
               onChange={(e) => onFilters({ ...filters, hits_only: e.target.checked })} />
        仅显示命中
      </label>
      <input ref={fileRef} type="file" accept=".pcap,.pcapng,.cap" style={{ display: "none" }}
             onChange={(e) => onFile(e.target.files?.[0])} />
    </div>
  );
}
