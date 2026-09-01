import React, { useRef, useState } from "react";
import { CloudUpload, Loader2, FileText, ScanLine, BotMessageSquare, ShieldAlert } from "lucide-react";

export default function UploadZone({ onFile, uploading, error }) {
  const inputRef = useRef(null);
  const [drag, setDrag] = useState(false);

  const openPicker = () => inputRef.current?.click();

  const handleDrop = (e) => {
    e.preventDefault();
    setDrag(false);
    const f = e.dataTransfer.files?.[0];
    if (f) onFile(f);
  };

  return (
    <div className="empty-state">
      <div className="empty-inner">
        <div
          className={`upload-zone${drag ? " dragover" : ""}`}
          onClick={openPicker}
          onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
          onDragLeave={() => setDrag(false)}
          onDrop={handleDrop}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") openPicker(); }}
          aria-label="上传 pcap 文件"
        >
          <div className="upload-icon">
            {uploading
              ? <Loader2 size={38} className="spin big-icon" />
              : <CloudUpload size={38} className="big-icon" />}
          </div>
          <div className="upload-title">
            {uploading ? "正在解析报文，请稍候…" : "拖入 pcap / pcapng 文件，或点击选择"}
          </div>
          <div className="upload-sub">纯本地解析，文件不会上传到任何服务器</div>
          <div className="upload-hint">支持 Wireshark / tcpdump 导出的抓包文件</div>
          <input ref={inputRef} type="file" accept=".pcap,.pcapng,.cap"
                 style={{ display: "none" }}
                 onChange={(e) => onFile(e.target.files?.[0])} />
        </div>
        {error && (
          <div className="ai-error" style={{ marginTop: 12, textAlign: "left" }}>
            <ShieldAlert size={15} style={{ verticalAlign: -2, marginRight: 6 }} />
            {error}
          </div>
        )}
        <div className="feature-chips">
          <span className="chip"><span className="chip-dot" style={{ background: "var(--coral)" }} />TCP RST 判断</span>
          <span className="chip"><span className="chip-dot" style={{ background: "var(--gold)" }} />重传 / 零窗口</span>
          <span className="chip"><span className="chip-dot" style={{ background: "var(--lavender)" }} />SYN 半开 / 端口扫描</span>
          <span className="chip"><span className="chip-dot" style={{ background: "var(--lake)" }} />DNS / HTTP / TLS / ICMP</span>
          <span className="chip"><BotMessageSquare size={13} />AI 分析（可选）</span>
          <span className="chip"><ScanLine size={13} />纯离线运行</span>
        </div>
      </div>
    </div>
  );
}
