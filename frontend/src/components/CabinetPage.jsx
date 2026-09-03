import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArchiveRestore, Boxes, Check, ChevronDown, ChevronLeft, ChevronRight, ChevronUp,
  GitCompare, Layers, LayoutGrid, Network, Plus, Save, Server, Trash2, Pencil, Copy,
} from "lucide-react";
import {
  fetchCabinetLayout, fetchCabinets, fetchCapacity, fetchRooms,
  createRoom, createCabinet, updateCabinet, deleteCabinet,
  duplicateCabinet, fetchTemplates, saveTemplate, applyTemplate, deleteTemplate,
  compareCabinets,
  createDevice, updateDevice, deleteDevice, fetchUnrackedDevices, placeDevice,
  createReservation, deleteReservation,
} from "../api.js";

const DEVICE_TYPES = ["交换机", "路由器", "防火墙", "服务器", "存储", "配线架", "PDU", "KVM", "光纤盒", "其他"];

function typeColor(type) {
  switch (type) {
    case "交换机": return "var(--iris)";
    case "路由器": case "KVM": return "var(--lavender)";
    case "防火墙": case "PDU": return "var(--coral)";
    case "服务器": case "光纤盒": return "var(--lake)";
    case "存储": return "var(--gold)";
    default: return "var(--fg-faint)";
  }
}

function ProgressBar({ label, used, limit, unit }) {
  if (!limit) return null;
  const pct = Math.min(100, (used / limit) * 100);
  const over = used > limit;
  const cls = over ? "cap-bar over" : pct > 80 ? "cap-bar warn" : "cap-bar";
  return (
    <div className="cap-item">
      <span className="cap-label">{label}</span>
      <div className="cap-track"><div className={cls} style={{ width: `${pct}%` }} /></div>
      <span className={`cap-num${over ? " cap-over" : ""}`}>
        {Math.round(used)} / {Math.round(limit)} {unit}
      </span>
    </div>
  );
}

function UCapacityBar({ used = 0, reserved = 0, total = 0 }) {
  if (!total) return null;
  const usedPct = Math.min(100, (used / total) * 100);
  const reservedPct = Math.min(100 - usedPct, (reserved / total) * 100);
  const over = used + reserved > total;
  return (
    <div className="cap-item cap-item-u">
      <div className="cap-line">
        <span className="cap-label">U 位</span>
        <span
          className={`cap-num cap-num-u${over ? " cap-over" : ""}`}
          title={`设备 ${used}U + 预留 ${reserved}U / ${total}U`}
        >
          设备 {used}U + 预留 {reserved}U / {total}U
        </span>
      </div>
      <div
        className={`cap-track cap-stack${over ? " over" : ""}`}
        role="img"
        aria-label={`设备占用 ${used}U，预留 ${reserved}U，总计 ${total}U`}
      >
        <span className="cap-segment used" style={{ width: `${usedPct}%` }} />
        <span className="cap-segment reserved" style={{ width: `${reservedPct}%` }} />
      </div>
    </div>
  );
}

function CapacityPanel({ value, compact = false }) {
  if (!value) return null;
  return (
    <div className={`cap-panel${compact ? " compact" : ""}`}>
      <div className="cap-head">容量使用</div>
      <UCapacityBar used={value.u_used} reserved={value.u_reserved} total={value.u_total} />
      {value.power_limit_w > 0 && (
        <ProgressBar label="功率" used={value.power_used} limit={value.power_limit_w} unit="W" />
      )}
      {value.weight_limit_kg > 0 && (
        <ProgressBar label="承重" used={value.weight_used} limit={value.weight_limit_kg} unit="kg" />
      )}
      <div className="cap-extra"><span>空闲 {value.u_free}U</span></div>
    </div>
  );
}

function CabinetView({ layout, onSlotClick, onSelect, selected = false }) {
  if (!layout) return null;
  const { cabinet, devices, reservations } = layout;
  const uTotal = cabinet.u_total;

  // Build a map: u -> occupant
  const map = {};
  for (const dev of devices) {
    if (dev.u_start == null || dev.status === "已下架") continue;
    const occ = { ...dev, _kind: "device" };
    for (let u = dev.u_start; u < dev.u_start + dev.u_size; u++) map[u] = occ;
  }
  for (const res of reservations) {
    const occ = { ...res, _kind: "reservation" };
    for (let u = res.u_start; u < res.u_start + res.u_size; u++) {
      if (!map[u]) map[u] = occ;
    }
  }

  // Group consecutive units of the same occupant into spans
  const rows = [];
  let u = uTotal;
  while (u >= 1) {
    const occ = map[u];
    if (occ) {
      let end = u;
      while (end >= 1 && map[end] === occ) end--;
      const span = u - end;
      rows.push({ occ, span, uTop: u, uBottom: end + 1 });
      u = end;
    } else {
      let end = u;
      while (end >= 1 && !map[end]) end--;
      const span = u - end;
      rows.push({ occ: null, span, uTop: u, uBottom: end + 1 });
      u = end;
    }
  }

  return (
    <div className="rack-view" role={onSelect ? "group" : "img"}
         aria-label={`机柜 ${cabinet.name} 正视图，共 ${uTotal}U`}>
      <div className="rack-header">
        <span className="rack-title-group">
          <span className="rack-name">{cabinet.name}</span>
          <span className="rack-meta">{cabinet.status} · {uTotal}U</span>
        </span>
        {onSelect && (
          <button
            type="button"
            className={`rack-select${selected ? " on" : ""}`}
            aria-pressed={selected}
            onClick={onSelect}
          >
            {selected && <Check size={11} />}{selected ? "当前台账" : "查看台账"}
          </button>
        )}
      </div>
      <div className="rack-body">
        {rows.map((row, i) => {
          const occ = row.occ;
          const isRes = occ?._kind === "reservation";
          const color = occ ? typeColor(occ.dev_type || "") : undefined;
          const style = {
            height: `calc(${row.span} * var(--u-h) + ${(row.span - 1) * 2}px)`,
            ...(color && occ ? { "--occ-color": color } : {}),
          };
          return (
            <div
              key={`${row.uBottom}-${i}`}
              className={occ
                ? `rack-slot occ ${isRes ? "reservation" : ""}`
                : "rack-slot free"}
              style={style}
              onClick={() => onSlotClick?.(row.uBottom, row.span, occ)}
              title={occ
                ? `${occ.name} · ${row.uBottom}U-${row.uTop}U${occ.mgmt_ip ? ` · ${occ.mgmt_ip}` : ""}`
                : `${row.uBottom}U-${row.uTop}U 空闲`}
            >
              <span className="rack-u">{row.uBottom}{row.span > 1 ? `-${row.uTop}` : ""}</span>
              <span className="rack-label">
                {occ ? occ.name : row.span >= 3 ? `空闲 ${row.span}U` : ""}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

const EXPANDED_ROW_LABELS = ["第一行", "第二行"];

function ExpandedRackRow({ rowIndex, cabinetIds, layouts, capacity, selectedCab, onSelect, loading }) {
  const scrollRef = useRef(null);
  const move = (direction) => {
    const element = scrollRef.current;
    if (!element) return;
    const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    element.scrollBy({
      left: direction * Math.max(320, element.clientWidth * 0.82),
      behavior: reducedMotion ? "auto" : "smooth",
    });
  };

  return (
    <section className="rack-row-shell" aria-labelledby={`rack-row-title-${rowIndex}`}>
      <div className="rack-row-head">
        <div>
          <span className="rack-row-title" id={`rack-row-title-${rowIndex}`}>
            {EXPANDED_ROW_LABELS[rowIndex]}
          </span>
          <span className="rack-row-count">{cabinetIds.length} 个机柜</span>
        </div>
        <span className="rack-row-hint">横向滑动查看</span>
        <button type="button" className="rack-row-arrow" aria-label={`${EXPANDED_ROW_LABELS[rowIndex]}向左滑动`}
                onClick={() => move(-1)}>
          <ChevronLeft size={15} />
        </button>
        <button type="button" className="rack-row-arrow" aria-label={`${EXPANDED_ROW_LABELS[rowIndex]}向右滑动`}
                onClick={() => move(1)}>
          <ChevronRight size={15} />
        </button>
      </div>
      {cabinetIds.length === 0 ? (
        <div className="rack-row-empty">请在上方将机柜分配到{EXPANDED_ROW_LABELS[rowIndex]}</div>
      ) : (
        <div ref={scrollRef} className="rack-row-scroll" tabIndex={0}
             aria-label={`${EXPANDED_ROW_LABELS[rowIndex]}机柜横向列表`} aria-busy={loading}>
          {cabinetIds.map((cabinetId, index) => {
            const expandedLayout = layouts[cabinetId];
            const expandedCapacity = capacity.find((item) => item.cabinet_id === cabinetId);
            if (!expandedLayout) {
              return (
                <div key={cabinetId} className="multi-rack-card rack-skeleton"
                     style={{ "--rack-index": index }} aria-label="正在加载机柜">
                  <span /><span /><span />
                </div>
              );
            }
            return (
              <article key={cabinetId}
                       className={`multi-rack-card${selectedCab === cabinetId ? " selected" : ""}`}
                       style={{ "--rack-index": index }}>
                <CabinetView layout={expandedLayout} selected={selectedCab === cabinetId}
                             onSelect={() => onSelect(cabinetId)} />
                <CapacityPanel value={expandedCapacity} compact />
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function Modal({ title, onClose, children }) {
  return (
    <div className="modal-mask" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal-box" role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-head">
          <span className="modal-title">{title}</span>
          <button className="btn btn-ghost btn-icon-only" onClick={onClose} aria-label="关闭">×</button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label className="form-field">
      <span className="form-label">{label}</span>
      {children}
    </label>
  );
}

export default function CabinetPage() {
  const [rooms, setRooms] = useState([]);
  const [selectedRoom, setSelectedRoom] = useState(null);
  const [cabinets, setCabinets] = useState([]);
  const [selectedCab, setSelectedCab] = useState(null);
  const [layout, setLayout] = useState(null);
  const [viewMode, setViewMode] = useState("single");
  const [expandedRowCount, setExpandedRowCount] = useState(1);
  const [expandedRows, setExpandedRows] = useState([[], []]);
  const [expandedLayouts, setExpandedLayouts] = useState({});
  const [expandedLoading, setExpandedLoading] = useState(false);
  const [capacity, setCapacity] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [unracked, setUnracked] = useState([]);
  const [showUnracked, setShowUnracked] = useState(true);
  const [error, setError] = useState("");
  const [version, setVersion] = useState(0);

  const [modal, setModal] = useState(null); // {type:'room'|'cabinet'|'device'|'reservation'|..., data}
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => setVersion((v) => v + 1), []);

  useEffect(() => {
    fetchRooms().then((rs) => {
      setRooms(rs);
      if (!selectedRoom || !rs.find((r) => r.id === selectedRoom)) setSelectedRoom(rs[0]?.id ?? null);
    }).catch((e) => setError(String(e.message || e)));
    fetchCapacity().then(setCapacity).catch(() => {});
    fetchTemplates().then((data) => setTemplates(data.templates || [])).catch(() => {});
    fetchUnrackedDevices().then(setUnracked).catch((e) => setError(String(e.message || e)));
  }, [version, selectedRoom]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!selectedRoom) { setCabinets([]); setSelectedCab(null); return; }
    fetchCabinets(selectedRoom).then((cs) => {
      setCabinets(cs);
      if (!selectedCab || !cs.find((c) => c.id === selectedCab)) setSelectedCab(cs[0]?.id ?? null);
      setExpandedRows((current) => {
        const validIds = new Set(cs.map((cabinet) => cabinet.id));
        const first = current[0].filter((id) => validIds.has(id));
        const firstIds = new Set(first);
        const second = current[1].filter((id) => validIds.has(id) && !firstIds.has(id));
        const assigned = new Set([...first, ...second]);
        for (const cabinet of cs) {
          if (!assigned.has(cabinet.id)) first.push(cabinet.id);
        }
        return [first, second];
      });
    }).catch(() => setCabinets([]));
  }, [version, selectedRoom]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!selectedCab) { setLayout(null); return; }
    fetchCabinetLayout(selectedCab).then(setLayout).catch(() => setLayout(null));
  }, [version, selectedCab]);

  useEffect(() => {
    if (cabinets.length < 2 && viewMode === "multi") setViewMode("single");
  }, [cabinets.length, viewMode]);

  const activeExpandedRows = useMemo(
    () => expandedRows.slice(0, expandedRowCount),
    [expandedRowCount, expandedRows],
  );
  const visibleCabinetIds = useMemo(
    () => [...new Set(activeExpandedRows.flat())],
    [activeExpandedRows],
  );
  const visibleCabinetKey = visibleCabinetIds.join(",");

  useEffect(() => {
    if (viewMode !== "multi" || !visibleCabinetIds.length) {
      setExpandedLoading(false);
      return undefined;
    }
    let active = true;
    setExpandedLoading(true);
    Promise.all(visibleCabinetIds.map(async (id) => [id, await fetchCabinetLayout(id)]))
      .then((entries) => {
        if (active) setExpandedLayouts(Object.fromEntries(entries));
      })
      .catch((err) => {
        if (active) setError(String(err.message || err));
      })
      .finally(() => {
        if (active) setExpandedLoading(false);
      });
    return () => { active = false; };
  }, [viewMode, version, selectedRoom, visibleCabinetKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const run = useCallback(async (fn, ...args) => {
    setBusy(true);
    setError("");
    try { await fn(...args); refresh(); setModal(null); }
    catch (err) { setError(String(err.message || err)); }
    finally { setBusy(false); }
  }, [refresh]);

  const cabCapacity = capacity.find((c) => c.cabinet_id === selectedCab);

  const changeExpandedRowCount = (count) => {
    setExpandedRows((current) => {
      if (count === 1) return [[...new Set([...current[0], ...current[1]])], []];
      if (current[1].length || current[0].length < 2) return current;
      const splitAt = Math.ceil(current[0].length / 2);
      return [current[0].slice(0, splitAt), current[0].slice(splitAt)];
    });
    setExpandedRowCount(count);
  };

  const assignCabinetToRow = (cabinetId, rowIndex) => {
    setExpandedRows((current) => {
      const next = current.map((row) => row.filter((id) => id !== cabinetId));
      if (rowIndex != null) next[rowIndex].push(cabinetId);
      return next;
    });
  };

  const distributeCabinets = () => {
    const ids = cabinets.map((cabinet) => cabinet.id);
    if (expandedRowCount === 1) {
      setExpandedRows([ids, []]);
      return;
    }
    const splitAt = Math.ceil(ids.length / 2);
    setExpandedRows([ids.slice(0, splitAt), ids.slice(splitAt)]);
  };

  return (
    <main className="cabinet-page">
      <div className="cabinet-sidebar">
        <div className="sidebar-head">
          <Boxes size={16} />
          <span>机房与机柜</span>
          <span className="grow" />
          <button className="btn btn-ghost btn-icon-only" title="新增机房" aria-label="新增机房"
                  onClick={() => setModal({ type: "room" })}><Plus size={15} /></button>
        </div>
        <div className="room-list">
          {rooms.map((room) => (
            <div key={room.id} className="room-group">
              <button className={room.id === selectedRoom ? "room-item on" : "room-item"}
                      onClick={() => { setSelectedRoom(room.id); setSelectedCab(null); }}>
                <Network size={13} /> {room.name}
              </button>
              {room.id === selectedRoom && cabinets.map((cab) => (
                <button key={cab.id}
                        className={cab.id === selectedCab ? "cab-item on" : "cab-item"}
                        onClick={() => setSelectedCab(cab.id)}>
                  <Server size={12} /> {cab.name}
                  <span className="cab-u">{cab.u_total}U</span>
                  <span className="grow" />
                  <span className="cab-actions" onClick={(e) => e.stopPropagation()}>
                    <button className="icon-btn" title="复制机柜" aria-label="复制机柜"
                            onClick={() => setModal({ type: "duplicate", data: cab })}><Copy size={12} /></button>
                    <button className="icon-btn" title="编辑机柜" aria-label="编辑机柜"
                            onClick={() => setModal({ type: "cabinet", data: cab })}><Pencil size={12} /></button>
                    <button className="icon-btn danger" title="删除机柜" aria-label="删除机柜"
                            onClick={() => { if (confirm(`确定删除机柜 ${cab.name}？设备将进入待上架列表，不会删除。`)) run(deleteCabinet, cab.id); }}>
                      <Trash2 size={12} /></button>
                  </span>
                </button>
              ))}
              {room.id === selectedRoom && (
                <button className="cab-item add-cab" onClick={() => setModal({ type: "cabinet" })}>
                  <Plus size={12} /> 新增机柜
                </button>
              )}
            </div>
          ))}
          {rooms.length === 0 && <div className="empty-hint">还没有机房，点击右上角 + 新建</div>}
        </div>
      </div>

      <div className="cabinet-main">
        {error && <div className="error-banner" role="alert" aria-live="polite">{error}</div>}
        {unracked.length > 0 && (
          <section className="unracked-panel" aria-labelledby="unracked-title">
            <button
              type="button"
              className="unracked-head"
              aria-expanded={showUnracked}
              aria-controls="unracked-list"
              onClick={() => setShowUnracked((value) => !value)}
            >
              <ArchiveRestore size={15} />
              <span id="unracked-title">待上架设备</span>
              <span className="unracked-count">{unracked.length}</span>
              <span className="grow" />
              <span className="unracked-hint">删除机柜或机房后，设备会安全保留在这里</span>
              {showUnracked ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
            </button>
            {showUnracked && (
              <div id="unracked-list" className="unracked-list">
                {unracked.map((dev) => {
                  const disabledReason = !selectedCab
                    ? "请先选择目标机柜"
                    : dev.status === "已下架"
                      ? "请先编辑设备状态，再重新上架"
                      : "";
                  return (
                    <div className="unracked-row" key={dev.id}>
                      <span className="dev-name">{dev.name}</span>
                      <span className="type-badge" style={{ "--type-color": typeColor(dev.dev_type) }}>{dev.dev_type}</span>
                      <span className="mono unracked-size">{dev.u_size}U</span>
                      <span><span className={`status-dot ${dev.status === "在用" ? "on" : dev.status === "已下架" ? "off" : "warn"}`} />{dev.status}</span>
                      <span className="unracked-actions">
                        <button
                          className="btn btn-ghost btn-compact"
                          disabled={Boolean(disabledReason)}
                          title={disabledReason || `上架到 ${layout?.cabinet?.name || "当前机柜"}`}
                          onClick={() => setModal({ type: "rack-device", data: dev })}
                        >
                          <ArchiveRestore size={13} /> 上架到当前机柜
                        </button>
                        <button className="icon-btn" title="编辑设备" aria-label={`编辑设备 ${dev.name}`}
                                onClick={() => setModal({ type: "unracked-device", data: dev })}><Pencil size={13} /></button>
                        <button className="icon-btn danger" title="删除设备" aria-label={`删除设备 ${dev.name}`}
                                onClick={() => { if (confirm(`确定删除待上架设备 ${dev.name}？此操作不可撤销。`)) run(deleteDevice, dev.id); }}>
                          <Trash2 size={13} />
                        </button>
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        )}
        {layout ? (
          <>
            {cabinets.length > 1 && (
              <section className="cabinet-view-controls" aria-label="机柜展开视图设置">
                <div className="view-mode-seg" role="tablist" aria-label="机柜查看方式">
                  <button type="button" role="tab" aria-selected={viewMode === "single"}
                          className={viewMode === "single" ? "on" : ""}
                          onClick={() => setViewMode("single")}>
                    <Server size={14} /> 单柜视图
                  </button>
                  <button type="button" role="tab" aria-selected={viewMode === "multi"}
                          className={viewMode === "multi" ? "on" : ""}
                          onClick={() => setViewMode("multi")}>
                    <LayoutGrid size={14} /> 展开视图
                  </button>
                </div>
                {viewMode === "multi" && (
                  <div className="expand-options">
                    <span className="expand-option-label">显示行数</span>
                    <div className="row-count-seg" role="group" aria-label="展开视图行数">
                      <button type="button" className={expandedRowCount === 1 ? "on" : ""}
                              aria-pressed={expandedRowCount === 1}
                              onClick={() => changeExpandedRowCount(1)}>一行</button>
                      <button type="button" className={expandedRowCount === 2 ? "on" : ""}
                              aria-pressed={expandedRowCount === 2}
                              onClick={() => changeExpandedRowCount(2)}>两行</button>
                    </div>
                    <span className="expanded-count">显示 {visibleCabinetIds.length} / {cabinets.length}</span>
                  </div>
                )}
              </section>
            )}

            {viewMode === "multi" && (
              <section className="rack-assignment-panel" aria-labelledby="rack-assignment-title">
                <div className="rack-assignment-head">
                  <div>
                    <span className="rack-assignment-title" id="rack-assignment-title">机柜分配</span>
                    <span className="rack-assignment-help">每个机柜可放入不同的横向滑动行</span>
                  </div>
                  <button type="button" className="btn btn-ghost btn-compact" onClick={distributeCabinets}>
                    {expandedRowCount === 2 ? "平均分配" : "全部放入第一行"}
                  </button>
                </div>
                <div className="rack-assignment-list">
                  {cabinets.map((cabinet) => {
                    const assignedRow = expandedRows.findIndex((row) => row.includes(cabinet.id));
                    return (
                      <div className="rack-assignment-item" key={cabinet.id}>
                        <span className="rack-assignment-name" title={cabinet.name}>{cabinet.name}</span>
                        <div className="rack-assignment-choice" role="group"
                             aria-label={`${cabinet.name}显示位置`}>
                          <button type="button" className={assignedRow === 0 ? "on" : ""}
                                  aria-pressed={assignedRow === 0}
                                  aria-label={`${cabinet.name}显示在第一行`}
                                  onClick={() => assignCabinetToRow(cabinet.id, 0)}>1</button>
                          {expandedRowCount === 2 && (
                            <button type="button" className={assignedRow === 1 ? "on" : ""}
                                    aria-pressed={assignedRow === 1}
                                    aria-label={`${cabinet.name}显示在第二行`}
                                    onClick={() => assignCabinetToRow(cabinet.id, 1)}>2</button>
                          )}
                          <button type="button" className={assignedRow < 0 ? "on muted" : ""}
                                  aria-pressed={assignedRow < 0}
                                  aria-label={`隐藏${cabinet.name}`}
                                  onClick={() => assignCabinetToRow(cabinet.id, null)}>隐藏</button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}

            <div className={`cabinet-grid ${viewMode === "multi" ? "multi-mode" : "single-mode"}`}>
              {viewMode === "single" ? (
                <div className="cabinet-col-view cabinet-view-enter">
                  <CabinetView layout={layout} />
                  <CapacityPanel value={cabCapacity} />
                </div>
              ) : (
                <section className="cabinet-overview" aria-label="多机柜展开视图">
                  {activeExpandedRows.map((cabinetIds, rowIndex) => (
                    <ExpandedRackRow
                      key={rowIndex}
                      rowIndex={rowIndex}
                      cabinetIds={cabinetIds}
                      layouts={expandedLayouts}
                      capacity={capacity}
                      selectedCab={selectedCab}
                      onSelect={setSelectedCab}
                      loading={expandedLoading}
                    />
                  ))}
                </section>
              )}

            <div className="cabinet-col-table cabinet-ledger-enter">
              <div className="table-head">
                <span className="table-title">设备台账</span>
                {viewMode === "multi" && <span className="current-cabinet-chip">当前：{layout.cabinet.name}</span>}
                <span className="grow" />
                <button className="btn btn-ghost" onClick={() => setModal({ type: "reservation" })}>
                  <Plus size={13} /> 预留 U 位
                </button>
                <button className="btn btn-ghost" onClick={() => setModal({ type: "save-template" })}
                        disabled={!selectedCab}>
                  <Save size={13} /> 存为模板
                </button>
                <button className="btn btn-ghost" onClick={() => setModal({ type: "apply-template" })}>
                  <Layers size={13} /> 模板创建
                </button>
                <button className="btn btn-ghost" onClick={() => setModal({ type: "compare" })}>
                  <GitCompare size={13} /> A/B 对比
                </button>
                <button className="btn btn-primary" onClick={() => setModal({ type: "device" })}>
                  <Plus size={13} /> 添加设备
                </button>
              </div>
              <div className="device-table-wrap">
                <table className="device-table">
                  <thead>
                    <tr>
                      <th>名称</th><th>类型</th><th>U 位</th><th>状态</th>
                      <th>IP</th><th>功耗</th><th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {layout.devices.map((dev) => (
                      <tr key={dev.id}>
                        <td className="dev-name">{dev.name}</td>
                        <td><span className="type-badge" style={{ "--type-color": typeColor(dev.dev_type) }}>{dev.dev_type}</span></td>
                        <td className="mono">{dev.u_start != null ? `${dev.u_start}U-${dev.u_start + dev.u_size - 1}U` : "未上架"}</td>
                        <td><span className={`status-dot ${dev.status === "在用" ? "on" : dev.status === "已下架" ? "off" : "warn"}`} />{dev.status}</td>
                        <td className="mono">{dev.mgmt_ip || "-"}</td>
                        <td className="mono">{dev.power_w > 0 ? `${dev.power_w}W` : "-"}</td>
                        <td className="dev-actions">
                          <button className="icon-btn" title="编辑" aria-label="编辑设备"
                                  onClick={() => setModal({ type: "device", data: dev })}><Pencil size={13} /></button>
                          <button className="icon-btn danger" title="删除" aria-label="删除设备"
                                  onClick={() => { if (confirm(`确定删除设备 ${dev.name}？`)) run(deleteDevice, dev.id); }}>
                            <Trash2 size={13} /></button>
                        </td>
                      </tr>
                    ))}
                    {layout.devices.length === 0 && (
                      <tr><td colSpan={7} className="empty-hint">暂无设备，点击右上角添加</td></tr>
                    )}
                  </tbody>
                </table>
                {layout.reservations.length > 0 && (
                  <div className="reservation-section">
                    <div className="res-title">U 位预留</div>
                    {layout.reservations.map((res) => (
                      <div key={res.id} className="res-row">
                        <span className="res-range mono">{res.u_start}-{res.u_start + res.u_size - 1}U</span>
                        <span className="res-label">{res.label}</span>
                        {res.owner && <span className="res-owner">{res.owner}</span>}
                        <span className="grow" />
                        <button className="icon-btn danger" title="取消预留" aria-label="取消预留"
                                onClick={() => run(deleteReservation, res.id)}><Trash2 size={12} /></button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
            </div>
          </>
        ) : (
          <div className="cabinet-empty">
            <Boxes size={40} />
            <p>{rooms.length === 0 ? "请先创建机房和机柜" : "请选择一个机柜"}</p>
          </div>
        )}
      </div>

      {modal?.type === "room" && <RoomModal onClose={() => setModal(null)} onSave={(d) => run(createRoom, d)} busy={busy} />}
      {modal?.type === "cabinet" && (
        <CabinetModal
          roomId={selectedRoom} data={modal.data}
          onClose={() => setModal(null)}
          onSave={(d) => modal.data ? run(updateCabinet, modal.data.id, d) : run(createCabinet, selectedRoom, d)}
          busy={busy}
        />
      )}
      {modal?.type === "duplicate" && (
        <DuplicateModal
          data={modal.data} rooms={rooms}
          onClose={() => setModal(null)}
          onSave={(newName, targetRoomId) => run(duplicateCabinet, modal.data.id, { new_name: newName, target_room_id: targetRoomId })}
          busy={busy}
        />
      )}
      {modal?.type === "save-template" && (
        <SaveTemplateModal
          data={modal.data || layout?.cabinet}
          onClose={() => setModal(null)}
          onSave={(d) => run(saveTemplate, selectedCab, d)}
          busy={busy}
        />
      )}
      {modal?.type === "apply-template" && (
        <ApplyTemplateModal
          templates={templates} rooms={rooms}
          onClose={() => setModal(null)}
          onSave={(id, d) => run(applyTemplate, id, d)}
          onDelete={(id) => run(deleteTemplate, id)}
          busy={busy}
        />
      )}
      {modal?.type === "compare" && (
        <CompareModal
          cabinets={[...cabinets]} rooms={rooms} selectedRoom={selectedRoom}
          selected={selectedCab}
          onClose={() => setModal(null)}
        />
      )}
      {modal?.type === "device" && (
        <DeviceModal
          data={modal.data} layout={layout}
          onClose={() => setModal(null)}
          onSave={(d) => modal.data ? run(updateDevice, modal.data.id, d, selectedCab) : run(createDevice, d, selectedCab)}
          busy={busy}
        />
      )}
      {modal?.type === "unracked-device" && (
        <DeviceModal
          data={modal.data} layout={null}
          onClose={() => setModal(null)}
          onSave={(d) => run(updateDevice, modal.data.id, d, null)}
          busy={busy}
        />
      )}
      {modal?.type === "rack-device" && (
        <RackDeviceModal
          device={modal.data} layout={layout}
          onClose={() => setModal(null)}
          onSave={(uStart) => run(placeDevice, modal.data.id, { cabinet_id: selectedCab, u_start: uStart })}
          busy={busy}
        />
      )}
      {modal?.type === "reservation" && (
        <ReservationModal
          layout={layout} onClose={() => setModal(null)}
          onSave={(d) => run(createReservation, d, selectedCab)}
          busy={busy}
        />
      )}
    </main>
  );
}

function RoomModal({ onClose, onSave, busy }) {
  const [name, setName] = useState("");
  const [location, setLocation] = useState("");
  return (
    <Modal title="新增机房" onClose={onClose}>
      <Field label="机房名称"><input autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="如：A1 机房" /></Field>
      <Field label="位置"><input value={location} onChange={(e) => setLocation(e.target.value)} placeholder="如：3 层东侧" /></Field>
      <div className="modal-foot">
        <button className="btn btn-ghost" onClick={onClose}>取消</button>
        <button className="btn btn-primary" disabled={busy || !name.trim()} onClick={() => onSave({ name: name.trim(), location })}>创建</button>
      </div>
    </Modal>
  );
}

function CabinetModal({ roomId, data, onClose, onSave, busy }) {
  const [name, setName] = useState(data?.name || "");
  const [uTotal, setUTotal] = useState(data?.u_total || 42);
  const [powerLimit, setPowerLimit] = useState(data?.power_limit_w ?? "");
  const [weightLimit, setWeightLimit] = useState(data?.weight_limit_kg ?? "");
  return (
    <Modal title={data ? "编辑机柜" : "新增机柜"} onClose={onClose}>
      <Field label="机柜名称"><input autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="如：A-01" /></Field>
      <Field label="总 U 数"><input type="number" min={1} max={100} value={uTotal} onChange={(e) => setUTotal(+e.target.value)} /></Field>
      <Field label="功率上限 (W)，选填"><input type="number" min={0} value={powerLimit} onChange={(e) => setPowerLimit(e.target.value)} placeholder="留空则不统计功率" /></Field>
      <Field label="承重上限 (kg)"><input type="number" min={0} value={weightLimit} onChange={(e) => setWeightLimit(e.target.value)} placeholder="选填" /></Field>
      <div className="modal-foot">
        <button className="btn btn-ghost" onClick={onClose}>取消</button>
        <button className="btn btn-primary" disabled={busy || !name.trim()} onClick={() => onSave({
          name: name.trim(), u_total: uTotal,
          power_limit_w: powerLimit ? +powerLimit : null,
          weight_limit_kg: weightLimit ? +weightLimit : null,
        })}>{data ? "保存" : "创建"}</button>
      </div>
    </Modal>
  );
}

function DeviceModal({ data, layout, onClose, onSave, busy }) {
  const [name, setName] = useState(data?.name || "");
  const [devType, setDevType] = useState(data?.dev_type || "服务器");
  const [uStart, setUStart] = useState(data?.u_start ?? "");
  const [uSize, setUSize] = useState(data?.u_size || 1);
  const [mgmtIp, setMgmtIp] = useState(data?.mgmt_ip || "");
  const [powerW, setPowerW] = useState(data?.power_w ?? "");
  const [status, setStatus] = useState(data?.status || "在用");
  const [model, setModel] = useState(data?.model || "");
  const [vendor, setVendor] = useState(data?.vendor || "");
  const [remark, setRemark] = useState(data?.remark || "");
  const uTotal = layout?.cabinet?.u_total || 42;

  return (
    <Modal title={data ? "编辑设备" : "添加设备"} onClose={onClose}>
      <div className="form-row">
        <Field label="设备名称"><input autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="如：sw-core-01" /></Field>
        <Field label="类型">
          <select value={devType} onChange={(e) => setDevType(e.target.value)}>
            {DEVICE_TYPES.map((t) => <option key={t}>{t}</option>)}
          </select>
        </Field>
      </div>
      <div className="form-row">
        <Field label="起始 U 位"><input type="number" min={1} max={uTotal} value={uStart} disabled={!layout} onChange={(e) => setUStart(e.target.value)} placeholder={layout ? "留空 = 未上架" : "请使用重新上架"} /></Field>
        <Field label="占用 U 数"><input type="number" min={1} max={100} value={uSize} onChange={(e) => setUSize(+e.target.value)} /></Field>
        <Field label="状态">
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option>在用</option><option>备用</option><option>维护中</option><option>已下架</option>
          </select>
        </Field>
      </div>
      <div className="form-row">
        <Field label="管理 IP"><input value={mgmtIp} onChange={(e) => setMgmtIp(e.target.value)} placeholder="选填" /></Field>
        <Field label="功耗 (W)"><input type="number" min={0} value={powerW} onChange={(e) => setPowerW(e.target.value)} placeholder="选填" /></Field>
      </div>
      <div className="form-row">
        <Field label="型号"><input value={model} onChange={(e) => setModel(e.target.value)} placeholder="选填" /></Field>
        <Field label="厂商"><input value={vendor} onChange={(e) => setVendor(e.target.value)} placeholder="选填" /></Field>
      </div>
      <Field label="备注"><input value={remark} onChange={(e) => setRemark(e.target.value)} placeholder="选填" /></Field>
      <div className="modal-foot">
        <button className="btn btn-ghost" onClick={onClose}>取消</button>
        <button className="btn btn-primary" disabled={busy || !name.trim()}
                onClick={() => onSave({
                  name: name.trim(), dev_type: devType,
                  u_start: uStart ? +uStart : null, u_size: uSize,
                  status, mgmt_ip: mgmtIp, power_w: powerW ? +powerW : 0,
                  model, vendor, remark,
                })}>{data ? "保存" : "添加"}</button>
      </div>
    </Modal>
  );
}

function RackDeviceModal({ device, layout, onClose, onSave, busy }) {
  const firstSlot = layout?.free_slots?.find((slot) => slot.u_size >= device.u_size);
  const [uStart, setUStart] = useState(firstSlot?.u_start ?? "");
  const maxStart = Math.max(1, (layout?.cabinet?.u_total || 1) - device.u_size + 1);
  return (
    <Modal title="重新上架设备" onClose={onClose}>
      <div className="rack-device-summary">
        <ArchiveRestore size={18} />
        <div>
          <strong>{device.name}</strong>
          <div className="modal-sub">{device.dev_type} · 占用 {device.u_size}U → {layout?.cabinet?.name}</div>
        </div>
      </div>
      <Field label="起始 U 位">
        <input
          autoFocus type="number" min={1} max={maxStart}
          value={uStart} onChange={(e) => setUStart(e.target.value)}
        />
      </Field>
      {firstSlot ? (
        <div className="modal-sub">已自动选择首个可容纳该设备的连续空闲区，可按需修改。</div>
      ) : (
        <div className="error-banner" role="alert">当前机柜没有足够的连续空闲 U 位。</div>
      )}
      <div className="modal-foot">
        <button className="btn btn-ghost" onClick={onClose}>取消</button>
        <button className="btn btn-primary" disabled={busy || !uStart || !firstSlot}
                onClick={() => onSave(+uStart)}>确认上架</button>
      </div>
    </Modal>
  );
}

function ReservationModal({ layout, onClose, onSave, busy }) {
  const [uStart, setUStart] = useState("");
  const [uSize, setUSize] = useState(1);
  const [label, setLabel] = useState("");
  const [owner, setOwner] = useState("");
  const uTotal = layout?.cabinet?.u_total || 42;
  return (
    <Modal title="预留 U 位" onClose={onClose}>
      <div className="form-row">
        <Field label="起始 U 位"><input autoFocus type="number" min={1} max={uTotal} value={uStart} onChange={(e) => setUStart(e.target.value)} /></Field>
        <Field label="占用 U 数"><input type="number" min={1} max={100} value={uSize} onChange={(e) => setUSize(+e.target.value)} /></Field>
      </div>
      <Field label="用途"><input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="如：新增核心交换" /></Field>
      <Field label="负责人"><input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="选填" /></Field>
      <div className="modal-foot">
        <button className="btn btn-ghost" onClick={onClose}>取消</button>
        <button className="btn btn-primary" disabled={busy || !uStart}
                onClick={() => onSave({ u_start: +uStart, u_size: uSize, label: label.trim() || "预留", owner })}>预留</button>
      </div>
    </Modal>
  );
}

function DuplicateModal({ data, rooms, onClose, onSave, busy }) {
  const [newName, setNewName] = useState(`${data?.name || ""}-copy`);
  const [targetRoom, setTargetRoom] = useState(data?.room_id || rooms[0]?.id);
  return (
    <Modal title="复制机柜" onClose={onClose}>
      <div className="modal-sub">
        将复制机柜 <strong>{data?.name}</strong> 的非已下架设备和 U 位预留到新机柜；设备状态将设为备用，管理 IP 留空。
      </div>
      <Field label="新机柜名称">
        <input autoFocus value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="如：C-01-B" />
      </Field>
      <Field label="目标机房">
        <select value={targetRoom} onChange={(e) => setTargetRoom(+e.target.value)}>
          {rooms.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
        </select>
      </Field>
      <div className="modal-foot">
        <button className="btn btn-ghost" onClick={onClose}>取消</button>
        <button className="btn btn-primary" disabled={busy || !newName.trim()}
                onClick={() => onSave(newName.trim(), targetRoom)}>复制</button>
      </div>
    </Modal>
  );
}

function SaveTemplateModal({ data, onClose, onSave, busy }) {
  const [name, setName] = useState(`${data?.name || ""}-template`);
  const [remark, setRemark] = useState("");
  return (
    <Modal title="保存机柜模板" onClose={onClose}>
      <div className="modal-sub">
        将保存 <strong>{data?.name}</strong> 的机柜规格、非已下架设备布局和 U 位预留。
      </div>
      <Field label="模板名称">
        <input autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="如：核心接入标准柜" />
      </Field>
      <Field label="说明"><input value={remark} onChange={(e) => setRemark(e.target.value)} placeholder="选填" /></Field>
      <div className="modal-foot">
        <button className="btn btn-ghost" onClick={onClose}>取消</button>
        <button className="btn btn-primary" disabled={busy || !name.trim()} onClick={() => onSave({ name: name.trim(), remark })}>保存</button>
      </div>
    </Modal>
  );
}

function ApplyTemplateModal({ templates, rooms, onClose, onSave, onDelete, busy }) {
  const [templateId, setTemplateId] = useState(templates[0]?.id || "");
  const [roomId, setRoomId] = useState(rooms[0]?.id || "");
  const [baseName, setBaseName] = useState("");
  const [count, setCount] = useState(1);
  const [startNumber, setStartNumber] = useState(1);
  const selected = templates.find((item) => item.id === +templateId);
  return (
    <Modal title="模板批量创建" onClose={onClose}>
      {templates.length === 0 ? (
        <div className="modal-sub">暂无模板。先选择一个机柜，点击“存为模板”。</div>
      ) : (
        <>
          <Field label="模板">
            <select value={templateId} onChange={(e) => setTemplateId(+e.target.value)}>
              {templates.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name} · {item.u_total}U · {item.devices?.length || 0} 台设备
                </option>
              ))}
            </select>
          </Field>
          {selected?.remark && <div className="modal-sub">{selected.remark}</div>}
          <div className="modal-sub">冗余部署会保留非已下架设备布局与规格，管理 IP 将保持为空。</div>
          <Field label="目标机房">
            <select value={roomId} onChange={(e) => setRoomId(+e.target.value)}>
              {rooms.map((room) => <option key={room.id} value={room.id}>{room.name}</option>)}
            </select>
          </Field>
          <Field label="基础名称">
            <input autoFocus value={baseName} onChange={(e) => setBaseName(e.target.value)} placeholder="如：C-01 或冗余柜" />
          </Field>
          <div className="form-row">
            <Field label="创建数量"><input type="number" min={1} max={64} value={count}
                    onChange={(e) => setCount(Math.max(1, Math.min(64, +e.target.value || 1)))} /></Field>
            <Field label="起始编号"><input type="number" min={1} value={startNumber}
                    onChange={(e) => setStartNumber(Math.max(1, +e.target.value || 1))} /></Field>
          </div>
          <div className="modal-sub">
            {count > 1 && /^.*\d+$/.test(baseName)
              ? `将按数字递增生成 ${count} 台机柜。`
              : `将生成 ${baseName || "机柜"}-01 到 ${baseName || "机柜"}-${String(count).padStart(2, "0")}。`}
          </div>
          <div className="modal-foot">
            <span className="grow" />
            <button className="btn btn-ghost danger-text" disabled={busy || !templateId}
                    onClick={() => { if (confirm("删除该模板？已创建的机柜不受影响。")) onDelete(+templateId); }}>删除模板</button>
            <button className="btn btn-ghost" onClick={onClose}>取消</button>
            <button className="btn btn-primary" disabled={busy || !templateId || !baseName.trim()}
                    onClick={() => onSave(+templateId, {
                      room_id: roomId, base_name: baseName.trim(), count, start_number: startNumber,
                    })}>创建</button>
          </div>
        </>
      )}
    </Modal>
  );
}

function CompareModal({ cabinets, selected, onClose }) {
  const [leftId, setLeftId] = useState(selected || cabinets[0]?.id || "");
  const [rightId, setRightId] = useState(cabinets[1]?.id || cabinets[0]?.id || "");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const runCompare = async () => {
    if (!leftId || !rightId || leftId === rightId) return;
    setBusy(true);
    setError("");
    try {
      setResult(await compareCabinets(+leftId, +rightId));
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title="A/B 冗余对比" onClose={onClose}>
      <div className="form-row">
        <Field label="基准机柜 A">
          <select value={leftId} onChange={(e) => setLeftId(+e.target.value)}>
            {cabinets.map((cab) => <option key={cab.id} value={cab.id}>{cab.name}</option>)}
          </select>
        </Field>
        <Field label="对照机柜 B">
          <select value={rightId} onChange={(e) => setRightId(+e.target.value)}>
            {cabinets.map((cab) => <option key={cab.id} value={cab.id}>{cab.name}</option>)}
          </select>
        </Field>
      </div>
      <button className="btn btn-primary" onClick={runCompare} disabled={busy || leftId === rightId}>开始对比</button>
      {error && <div className="ai-error">{error}</div>}
      {result && (
        <div className="compare-result">
          <div className={`status-badge ${result.identical ? "st-ok" : "st-warn"}`}>
            {result.identical ? "布局一致" : `发现 ${result.changes.length} 处差异`}
          </div>
          {result.changes.map((change, index) => (
            <div key={index} className="diff-item">
              <span className="mono-cell">{change.u}</span>
              <span className={`status-badge ${change.side === "left_only" ? "st-warn" : "st-err"}`}>
                {change.side === "left_only" ? "仅 A 有" : "仅 B 有"}
              </span>
              <span>{change.kind === "device" ? "设备" : "预留"}：{change.name}</span>
            </div>
          ))}
          {result.identical && <div className="modal-sub">设备与 U 位预留一致，管理 IP 和运行状态不参与冗余对比。</div>}
        </div>
      )}
    </Modal>
  );
}
