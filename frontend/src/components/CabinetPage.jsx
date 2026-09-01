import React, { useCallback, useEffect, useState } from "react";
import {
  Boxes, ChevronLeft, Cpu, HardDrive, Network, Plus, Server, Trash2, Pencil,
} from "lucide-react";
import {
  fetchCabinetLayout, fetchCabinets, fetchCapacity, fetchRooms,
  createRoom, createCabinet, updateCabinet, deleteCabinet,
  createDevice, updateDevice, deleteDevice,
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

function CabinetView({ layout, onSlotClick }) {
  if (!layout) return null;
  const { cabinet, devices, reservations } = layout;
  const uTotal = cabinet.u_total;

  // Build a map: u -> occupant
  const map = {};
  for (const dev of devices) {
    if (dev.u_start == null) continue;
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
    <div className="rack-view" role="img" aria-label={`机柜 ${cabinet.name} 正视图，共 ${uTotal}U`}>
      <div className="rack-header">
        <span className="rack-name">{cabinet.name}</span>
        <span className="rack-meta">{cabinet.status} · {uTotal}U</span>
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
  const [capacity, setCapacity] = useState([]);
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
  }, [version, selectedRoom]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!selectedRoom) { setCabinets([]); setSelectedCab(null); return; }
    fetchCabinets(selectedRoom).then((cs) => {
      setCabinets(cs);
      if (!selectedCab || !cs.find((c) => c.id === selectedCab)) setSelectedCab(cs[0]?.id ?? null);
    }).catch(() => setCabinets([]));
  }, [version, selectedRoom]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!selectedCab) { setLayout(null); return; }
    fetchCabinetLayout(selectedCab).then(setLayout).catch(() => setLayout(null));
  }, [version, selectedCab]);

  const run = useCallback(async (fn, ...args) => {
    setBusy(true);
    setError("");
    try { await fn(...args); refresh(); setModal(null); }
    catch (err) { setError(String(err.message || err)); }
    finally { setBusy(false); }
  }, [refresh]);

  const cabCapacity = capacity.find((c) => c.cabinet_id === selectedCab);

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
                    <button className="icon-btn" title="编辑机柜" aria-label="编辑机柜"
                            onClick={() => setModal({ type: "cabinet", data: cab })}><Pencil size={12} /></button>
                    <button className="icon-btn danger" title="删除机柜" aria-label="删除机柜"
                            onClick={() => { if (confirm(`确定删除机柜 ${cab.name}？设备将解除关联`)) run(deleteCabinet, cab.id); }}>
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
        {error && <div className="error-banner">{error}</div>}
        {layout ? (
          <div className="cabinet-grid">
            <div className="cabinet-col-view">
              <CabinetView layout={layout} />
              {cabCapacity && (
                <div className="cap-panel">
                  <div className="cap-head">容量使用</div>
                  <ProgressBar label="U 位" used={cabCapacity.u_used} limit={cabCapacity.u_total} unit="U" />
                  {cabCapacity.power_limit_w > 0 && (
                    <ProgressBar label="功率" used={cabCapacity.power_used} limit={cabCapacity.power_limit_w} unit="W" />
                  )}
                  {cabCapacity.weight_limit_kg > 0 && (
                    <ProgressBar label="承重" used={cabCapacity.weight_used} limit={cabCapacity.weight_limit_kg} unit="kg" />
                  )}
                  <div className="cap-extra">
                    <span>已预留 {cabCapacity.u_reserved}U</span>
                    <span>空闲 {cabCapacity.u_free}U</span>
                  </div>
                </div>
              )}
            </div>

            <div className="cabinet-col-table">
              <div className="table-head">
                <span className="table-title">设备台账</span>
                <span className="grow" />
                <button className="btn btn-ghost" onClick={() => setModal({ type: "reservation" })}>
                  <Plus size={13} /> 预留 U 位
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
      {modal?.type === "device" && (
        <DeviceModal
          data={modal.data} layout={layout}
          onClose={() => setModal(null)}
          onSave={(d, cid) => modal.data ? run(updateDevice, modal.data.id, d, cid) : run(createDevice, d, cid)}
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
        <Field label="起始 U 位"><input type="number" min={1} max={uTotal} value={uStart} onChange={(e) => setUStart(e.target.value)} placeholder="留空 = 未上架" /></Field>
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
