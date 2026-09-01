import React from "react";
import { X, Layers } from "lucide-react";

function renderHex(hex) {
  if (!hex) return <div className="hex-empty">无载荷数据</div>;
  const lines = [];
  for (let i = 0; i < hex.length; i += 32) {
    const chunk = hex.slice(i, i + 32);
    const offset = (i / 2).toString(16).padStart(4, "0");
    const bytes = chunk.match(/.{2}/g) || [];
    const hexPart = bytes.join(" ").padEnd(47, " ");
    const ascii = bytes.map((b) => {
      const v = parseInt(b, 16);
      return v >= 32 && v < 127 ? String.fromCharCode(v) : ".";
    }).join("");
    lines.push(`${offset}  ${hexPart}  |${ascii}|`);
  }
  return <div className="hex-box">{lines.join("\n")}</div>;
}

function JsonBox({ data, title }) {
  if (!data) return null;
  return (
    <div>
      <p className="section-title">{title}</p>
      <pre className="hex-box" style={{ whiteSpace: "pre-wrap" }}>
        {JSON.stringify(data, null, 2)}
      </pre>
    </div>
  );
}

export default function DetailDrawer({ detail, ruleNames, onClose }) {
  const flagsStr = detail.tcp_flags
    ? `${detail.tcp_flags} (${detail.flags_meaning})` : "—";
  return (
    <>
      <div className="drawer-mask" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`报文 ${detail.no} 详情`}>
        <div className="drawer-head">
          <Layers size={17} style={{ color: "var(--iris)" }} />
          <h3>报文 #{detail.no}</h3>
          <span style={{ marginLeft: "auto" }} />
          <button className="btn btn-ghost btn-icon-only" onClick={onClose} aria-label="关闭">
            <X size={16} />
          </button>
        </div>
        <div className="drawer-body">
          <div>
            <p className="section-title">基本信息</p>
            <dl className="kv-grid">
              <dt>源</dt><dd>{detail.src_mac} ({detail.src}{detail.sport ? `:${detail.sport}` : ""})</dd>
              <dt>目的</dt><dd>{detail.dst_mac} ({detail.dst}{detail.dport ? `:${detail.dport}` : ""})</dd>
              <dt>协议</dt><dd>{detail.proto}</dd>
              <dt>帧长</dt><dd>{detail.frame_len} 字节</dd>
              <dt>时间</dt><dd>{new Date(detail.ts * 1000).toISOString()}</dd>
              <dt>流</dt><dd style={{ wordBreak: "break-all" }}>{detail.flow || "—"}</dd>
            </dl>
          </div>
          {detail.proto === "TCP" && (
            <div>
              <p className="section-title">TCP 头</p>
              <dl className="kv-grid">
                <dt>Flags</dt><dd>{flagsStr}</dd>
                <dt>Seq / Ack</dt><dd>{detail.seq} / {detail.ack}</dd>
                <dt>Window</dt><dd>{detail.window}</dd>
                <dt>载荷</dt><dd>{detail.payload_len} 字节</dd>
              </dl>
            </div>
          )}
          <div>
            <p className="section-title">规则命中</p>
            {(detail.hits || []).length === 0 && <div className="hex-empty">无</div>}
            {(detail.hits || []).map((h, i) => (
              <div key={i} className={`hit-card sev-${h.severity}`}>
                <div className="hit-verdict">{h.name}：{h.verdict}</div>
                <div className="hit-detail">{h.detail}</div>
              </div>
            ))}
          </div>
          <JsonBox data={detail.dns} title="DNS" />
          <JsonBox data={detail.http} title="HTTP" />
          <JsonBox data={detail.tls} title="TLS" />
          <JsonBox data={detail.icmp} title="ICMP" />
          <div>
            <p className="section-title">载荷预览（前 96 字节）</p>
            {renderHex(detail.payload_preview)}
          </div>
        </div>
      </aside>
    </>
  );
}
