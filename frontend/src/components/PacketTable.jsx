import React from "react";
import { AlertTriangle, ShieldAlert, Info } from "lucide-react";

const SEV_ICON = {
  error: <ShieldAlert size={11} />,
  warning: <AlertTriangle size={11} />,
  info: <Info size={11} />,
};

function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const pad = (n, w = 2) => String(n).padStart(w, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

export default function PacketTable({ rows, selection, activeNo, onToggle, onRowClick }) {
  return (
    <table className="pkt-table">
      <thead>
        <tr>
          <th style={{ width: 36 }}></th>
          <th style={{ width: 64 }}>No.</th>
          <th style={{ width: 110 }}>时间</th>
          <th style={{ width: 180 }}>源</th>
          <th style={{ width: 180 }}>目的</th>
          <th style={{ width: 70 }}>协议</th>
          <th>信息</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => {
          const protoClass = `proto-${["TCP", "UDP", "ICMP", "ARP"].includes(row.proto) ? row.proto : "other"}`;
          return (
            <tr key={row.no}
                className={activeNo === row.no ? "active" : ""}
                tabIndex={0}
                onClick={() => onRowClick(row)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onRowClick(row);
                  }
                }}>
              <td onClick={(e) => e.stopPropagation()}>
                <input type="checkbox" checked={selection.has(row.no)}
                       onChange={() => onToggle(row.no)}
                       aria-label={`选中报文 ${row.no}`} />
              </td>
              <td className="cell-no">{row.no}</td>
              <td className="cell-time">{fmtTime(row.ts)}</td>
              <td className="cell-endpoint">{row.sport ? `${row.src}:${row.sport}` : row.src}</td>
              <td className="cell-endpoint">{row.dport ? `${row.dst}:${row.dport}` : row.dst}</td>
              <td><span className={`proto-tag ${protoClass}`}>{row.proto}</span></td>
              <td>
                <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                  {row.hits?.map((h, i) => (
                    <span key={i} className={`hit-badge hit-${h.severity}`}
                          title={`${h.name}：${h.detail}`}>
                      {SEV_ICON[h.severity]}
                      {h.name}
                    </span>
                  ))}
                  <span className="cell-info" title={row.info}>{row.info}</span>
                </div>
              </td>
            </tr>
          );
        })}
        {rows.length === 0 && (
          <tr>
            <td colSpan={7} style={{ textAlign: "center", padding: 40, color: "var(--fg-faint)" }}>
              没有匹配的报文
            </td>
          </tr>
        )}
      </tbody>
    </table>
  );
}
