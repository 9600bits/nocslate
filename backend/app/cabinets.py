"""Cabinet management: rooms, cabinets, devices, U-position occupancy and capacity."""

from __future__ import annotations

import sqlite3
import sys
import threading
import json
import re
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


class RoomIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    code: str = ""
    location: str = ""
    remark: str = ""


class CabinetIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    code: str = ""
    u_total: int = Field(default=42, ge=1, le=100)
    power_limit_w: Optional[float] = Field(default=None, ge=0)
    weight_limit_kg: Optional[float] = Field(default=None, ge=0)
    status: str = "在用"
    remark: str = ""


class DeviceIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    u_start: Optional[int] = Field(default=None, ge=1)
    u_size: int = Field(default=1, ge=1, le=100)
    dev_type: str = "其他"
    status: str = "在用"
    model: str = ""
    vendor: str = ""
    mgmt_ip: str = ""
    power_w: float = 0
    weight_kg: float = 0
    remark: str = ""


class ReservationIn(BaseModel):
    u_start: int = Field(ge=1)
    u_size: int = Field(default=1, ge=1, le=100)
    label: str = "预留"
    project: str = ""
    owner: str = ""
    remark: str = ""


class PlacementCheckIn(BaseModel):
    u_start: Optional[int] = Field(default=None, ge=1)
    u_size: int = Field(default=1, ge=1, le=100)
    exclude_kind: str = ""
    exclude_id: int = 0


class DuplicateIn(BaseModel):
    new_name: str = Field(min_length=1, max_length=64)
    target_room_id: Optional[int] = None


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    remark: str = Field(default="", max_length=255)


class TemplateApplyIn(BaseModel):
    room_id: int
    base_name: str = Field(min_length=1, max_length=64)
    count: int = Field(default=1, ge=1, le=64)
    start_number: int = Field(default=1, ge=1, le=9999)


def db_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "cabinets.db"
    return Path(__file__).resolve().parent.parent / "cabinets.db"


class CabinetStore:
    """Thread-safe wrapper around one SQLite connection (WAL mode)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path(), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS room (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    code TEXT NOT NULL DEFAULT '',
                    location TEXT NOT NULL DEFAULT '',
                    remark TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS cabinet (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_id INTEGER NOT NULL REFERENCES room(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    code TEXT NOT NULL DEFAULT '',
                    u_total INTEGER NOT NULL DEFAULT 42 CHECK (u_total > 0 AND u_total <= 100),
                    power_limit_w REAL,
                    weight_limit_kg REAL,
                    status TEXT NOT NULL DEFAULT '在用',
                    remark TEXT NOT NULL DEFAULT '',
                    UNIQUE (room_id, name)
                );
                CREATE TABLE IF NOT EXISTS device (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cabinet_id INTEGER REFERENCES cabinet(id) ON DELETE SET NULL,
                    name TEXT NOT NULL,
                    u_start INTEGER,
                    u_size INTEGER NOT NULL DEFAULT 1 CHECK (u_size >= 1),
                    dev_type TEXT NOT NULL DEFAULT '其他',
                    status TEXT NOT NULL DEFAULT '在用',
                    model TEXT NOT NULL DEFAULT '',
                    vendor TEXT NOT NULL DEFAULT '',
                    mgmt_ip TEXT NOT NULL DEFAULT '',
                    power_w REAL NOT NULL DEFAULT 0,
                    weight_kg REAL NOT NULL DEFAULT 0,
                    remark TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
                );
                CREATE TABLE IF NOT EXISTS reservation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cabinet_id INTEGER NOT NULL REFERENCES cabinet(id) ON DELETE CASCADE,
                    u_start INTEGER NOT NULL,
                    u_size INTEGER NOT NULL DEFAULT 1 CHECK (u_size >= 1),
                    label TEXT NOT NULL DEFAULT '预留',
                    project TEXT NOT NULL DEFAULT '',
                    owner TEXT NOT NULL DEFAULT '',
                    remark TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
                );
                CREATE INDEX IF NOT EXISTS idx_cabinet_room ON cabinet(room_id);
                CREATE INDEX IF NOT EXISTS idx_device_cabinet ON device(cabinet_id);
                CREATE INDEX IF NOT EXISTS idx_reservation_cabinet ON reservation(cabinet_id);
                CREATE TABLE IF NOT EXISTS cabinet_template (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    remark TEXT NOT NULL DEFAULT '',
                    u_total INTEGER NOT NULL,
                    power_limit_w REAL,
                    weight_limit_kg REAL,
                    status TEXT NOT NULL DEFAULT '在用',
                    devices_json TEXT NOT NULL DEFAULT '[]',
                    reservations_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
                    updated_at TEXT NOT NULL DEFAULT (datetime('now','localtime'))
                );
            """)
            self._conn.commit()

    def query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]

    def query_one(self, sql: str, params: tuple = ()) -> Optional[dict[str, Any]]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def scalar(self, sql: str, params: tuple = (), default: Any = 0) -> Any:
        row = self.query_one(sql, params)
        if row is None:
            return default
        return next(iter(row.values()), default)

    def execute(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------- occupancy ----------

    def _occupants(self, cabinet_id: int, exclude_kind: str = "", exclude_id: int = 0) -> list[dict]:
        devices = self.query(
            "SELECT id, name, u_start, u_size FROM device "
            "WHERE cabinet_id=? AND u_start IS NOT NULL AND status <> '已下架'",
            (cabinet_id,),
        )
        reservations = self.query(
            "SELECT id, label, u_start, u_size FROM reservation WHERE cabinet_id=?",
            (cabinet_id,),
        )
        result = []
        for row in devices:
            if exclude_kind == "device" and row["id"] == exclude_id:
                continue
            result.append({"kind": "device", **row})
        for row in reservations:
            if exclude_kind == "reservation" and row["id"] == exclude_id:
                continue
            result.append({"kind": "reservation", **row})
        return result

    def check_placement(
        self, cabinet_id: int, u_start: Optional[int], u_size: int,
        exclude_kind: str = "", exclude_id: int = 0,
    ) -> dict[str, Any]:
        if u_start is None:
            return {"ok": True, "conflicts": []}
        cab = self.query_one("SELECT u_total, name FROM cabinet WHERE id=?", (cabinet_id,))
        if cab is None:
            return {"ok": False, "conflicts": [], "message": "机柜不存在"}
        u_end = u_start + u_size - 1
        if u_end > cab["u_total"]:
            return {
                "ok": False, "conflicts": [],
                "message": f"超出机柜范围：{cab['name']} 共 {cab['u_total']}U，占用 {u_start}-{u_end}",
            }
        hits = []
        for occ in self._occupants(cabinet_id, exclude_kind, exclude_id):
            occ_end = occ["u_start"] + occ["u_size"] - 1
            if u_start <= occ_end and occ["u_start"] <= u_end:
                hits.append(f"{occ['name']}（{occ['u_start']}-{occ_end}U）")
        if hits:
            return {"ok": False, "conflicts": hits, "message": f"U 位冲突：已被 {'、'.join(hits)} 占用"}
        return {"ok": True, "conflicts": []}

    def free_slots(self, cabinet_id: int) -> list[dict[str, int]]:
        cab = self.query_one("SELECT u_total FROM cabinet WHERE id=?", (cabinet_id,))
        if cab is None:
            return []
        taken: set[int] = set()
        for occ in self._occupants(cabinet_id):
            for u in range(occ["u_start"], occ["u_start"] + occ["u_size"]):
                taken.add(u)
        slots = []
        start = None
        for u in range(1, cab["u_total"] + 1):
            if u not in taken:
                if start is None:
                    start = u
            elif start is not None:
                slots.append({"u_start": start, "u_size": u - start})
                start = None
        if start is not None:
            slots.append({"u_start": start, "u_size": cab["u_total"] - start + 1})
        return slots

    # ---------- rooms ----------

    def list_rooms(self) -> list[dict]:
        return self.query("SELECT * FROM room ORDER BY name")

    def create_room(self, data: RoomIn) -> dict:
        if self.query_one("SELECT id FROM room WHERE name=?", (data.name,)):
            raise ValueError(f"机房名称已存在：{data.name}")
        rid = self.execute(
            "INSERT INTO room(name, code, location, remark) VALUES(?,?,?,?)",
            (data.name, data.code, data.location, data.remark),
        )
        return self.query_one("SELECT * FROM room WHERE id=?", (rid,))

    def delete_room(self, room_id: int) -> None:
        self.execute("DELETE FROM room WHERE id=?", (room_id,))

    # ---------- cabinets ----------

    def list_cabinets(self, room_id: Optional[int] = None) -> list[dict]:
        sql = "SELECT * FROM cabinet"
        params: list = []
        if room_id is not None:
            sql += " WHERE room_id=?"
            params.append(room_id)
        sql += " ORDER BY name"
        return self.query(sql, tuple(params))

    def create_cabinet(self, room_id: int, data: CabinetIn) -> dict:
        if not self.query_one("SELECT id FROM room WHERE id=?", (room_id,)):
            raise ValueError("机房不存在")
        if self.query_one("SELECT id FROM cabinet WHERE room_id=? AND name=?", (room_id, data.name)):
            raise ValueError(f"该机房下机柜名称已存在：{data.name}")
        cid = self.execute(
            "INSERT INTO cabinet(room_id, name, code, u_total, power_limit_w, weight_limit_kg, status, remark) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (room_id, data.name, data.code, data.u_total, data.power_limit_w, data.weight_limit_kg,
             data.status, data.remark),
        )
        return self.query_one("SELECT * FROM cabinet WHERE id=?", (cid,))

    def update_cabinet(self, cabinet_id: int, data: CabinetIn) -> dict:
        cab = self.query_one("SELECT room_id FROM cabinet WHERE id=?", (cabinet_id,))
        if cab is None:
            raise ValueError("机柜不存在")
        dup = self.query_one(
            "SELECT id FROM cabinet WHERE room_id=? AND name=? AND id<>?",
            (cab["room_id"], data.name, cabinet_id),
        )
        if dup:
            raise ValueError(f"该机房下机柜名称已存在：{data.name}")
        self.execute(
            "UPDATE cabinet SET name=?, code=?, u_total=?, power_limit_w=?, weight_limit_kg=?, "
            "status=?, remark=? WHERE id=?",
            (data.name, data.code, data.u_total, data.power_limit_w, data.weight_limit_kg,
             data.status, data.remark, cabinet_id),
        )
        return self.query_one("SELECT * FROM cabinet WHERE id=?", (cabinet_id,))

    def delete_cabinet(self, cabinet_id: int) -> None:
        self.execute("DELETE FROM cabinet WHERE id=?", (cabinet_id,))

    def duplicate_cabinet(self, cabinet_id: int, new_name: str, target_room_id: Optional[int] = None) -> dict:
        """Copy a cabinet with its devices and reservations (offset to same U positions)."""
        src = self.query_one("SELECT * FROM cabinet WHERE id=?", (cabinet_id,))
        if src is None:
            raise ValueError("源机柜不存在")
        room_id = target_room_id if target_room_id is not None else src["room_id"]
        if not self.query_one("SELECT id FROM room WHERE id=?", (room_id,)):
            raise ValueError("目标机房不存在")
        if self.query_one("SELECT id FROM cabinet WHERE room_id=? AND name=?", (room_id, new_name)):
            raise ValueError(f"目标机房下机柜名称已存在：{new_name}")

        new_id = self.execute(
            "INSERT INTO cabinet(room_id, name, code, u_total, power_limit_w, weight_limit_kg, status, remark) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (room_id, new_name, src["code"], src["u_total"], src["power_limit_w"],
             src["weight_limit_kg"], src["status"], src["remark"]),
        )
        devices = self.query(
            "SELECT * FROM device WHERE cabinet_id=? AND status <> '已下架'", (cabinet_id,)
        )
        for dev in devices:
            self.execute(
                "INSERT INTO device(cabinet_id, name, u_start, u_size, dev_type, status, model, vendor, "
                "mgmt_ip, power_w, weight_kg, remark) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (new_id, dev["name"], dev["u_start"], dev["u_size"], dev["dev_type"], "备用",
                 dev["model"], dev["vendor"], "", dev["power_w"], dev["weight_kg"], dev["remark"]),
            )
        reservations = self.query(
            "SELECT * FROM reservation WHERE cabinet_id=?", (cabinet_id,)
        )
        for res in reservations:
            self.execute(
                "INSERT INTO reservation(cabinet_id, u_start, u_size, label, project, owner, remark) "
                "VALUES(?,?,?,?,?,?,?)",
                (new_id, res["u_start"], res["u_size"], res["label"], res["project"],
                 res["owner"], res["remark"]),
            )
        return self.query_one("SELECT * FROM cabinet WHERE id=?", (new_id,))

    # ---------- templates & redundancy comparison ----------

    def save_template(self, cabinet_id: int, data: TemplateIn) -> dict[str, Any]:
        cab = self.query_one("SELECT * FROM cabinet WHERE id=?", (cabinet_id,))
        if cab is None:
            raise ValueError("机柜不存在")
        if self.query_one("SELECT id FROM cabinet_template WHERE name=?", (data.name,)):
            raise ValueError(f"模板名称已存在：{data.name}")
        devices = self.query(
            "SELECT name,u_start,u_size,dev_type,status,model,vendor,power_w,weight_kg,remark "
            "FROM device WHERE cabinet_id=? AND status<>'已下架' ORDER BY u_start, id", (cabinet_id,)
        )
        reservations = self.query(
            "SELECT u_start,u_size,label,project,owner,remark FROM reservation "
            "WHERE cabinet_id=? ORDER BY u_start, id", (cabinet_id,)
        )
        template_id = self.execute(
            "INSERT INTO cabinet_template(name,remark,u_total,power_limit_w,weight_limit_kg,status,"
            "devices_json,reservations_json) VALUES(?,?,?,?,?,?,?,?)",
            (
                data.name, data.remark, cab["u_total"], cab["power_limit_w"], cab["weight_limit_kg"],
                cab["status"], json.dumps(devices, ensure_ascii=False),
                json.dumps(reservations, ensure_ascii=False),
            ),
        )
        return self.query_one("SELECT * FROM cabinet_template WHERE id=?", (template_id,))  # type: ignore[return-value]

    def list_templates(self) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM cabinet_template ORDER BY name")
        for row in rows:
            row["devices"] = json.loads(row.pop("devices_json"))
            row["reservations"] = json.loads(row.pop("reservations_json"))
        return rows

    def delete_template(self, template_id: int) -> None:
        self.execute("DELETE FROM cabinet_template WHERE id=?", (template_id,))

    def _template_names(self, base_name: str, count: int, start_number: int) -> list[str]:
        if count == 1:
            return [base_name]
        match = re.fullmatch(r"^(.*?)(\d+)$", base_name)
        if not match:
            return [f"{base_name}-{index:02d}" for index in range(start_number, start_number + count)]
        prefix, number = match.groups()
        width = len(number)
        return [
            f"{prefix}{str(start_number + offset).zfill(width)}"
            for offset in range(count)
        ]

    def apply_template(self, template_id: int, data: TemplateApplyIn) -> list[dict[str, Any]]:
        template = self.query_one("SELECT * FROM cabinet_template WHERE id=?", (template_id,))
        if template is None:
            raise ValueError("模板不存在")
        if not self.query_one("SELECT id FROM room WHERE id=?", (data.room_id,)):
            raise ValueError("目标机房不存在")
        devices = json.loads(template["devices_json"])
        reservations = json.loads(template["reservations_json"])
        created: list[dict[str, Any]] = []
        names = self._template_names(data.base_name.strip(), data.count, data.start_number)
        for name in names:
            if self.query_one("SELECT id FROM cabinet WHERE room_id=? AND name=?", (data.room_id, name)):
                raise ValueError(f"该机房下机柜名称已存在：{name}")
            cid = self.execute(
                "INSERT INTO cabinet(room_id,name,code,u_total,power_limit_w,weight_limit_kg,status,remark) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (data.room_id, name, "", template["u_total"], template["power_limit_w"],
                 template["weight_limit_kg"], template["status"], f"由模板 {template['name']} 创建"),
            )
            for dev in devices:
                self.execute(
                    "INSERT INTO device(cabinet_id,name,u_start,u_size,dev_type,status,model,vendor,"
                    "mgmt_ip,power_w,weight_kg,remark) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (cid, dev["name"], dev["u_start"], dev["u_size"], dev["dev_type"], dev["status"],
                     dev["model"], dev["vendor"], "", dev["power_w"], dev["weight_kg"], dev["remark"]),
                )
            for res in reservations:
                self.execute(
                    "INSERT INTO reservation(cabinet_id,u_start,u_size,label,project,owner,remark) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (cid, res["u_start"], res["u_size"], res["label"], res["project"], res["owner"], res["remark"]),
                )
            created.append(self.query_one("SELECT * FROM cabinet WHERE id=?", (cid,)))  # type: ignore[arg-type]
        return created

    def compare_cabinets(self, left_id: int, right_id: int) -> dict[str, Any]:
        left_layout = self.cabinet_layout(left_id)
        right_layout = self.cabinet_layout(right_id)

        def device_signature(dev: dict[str, Any]) -> tuple:
            return (
                dev.get("name", ""), dev.get("u_start"), dev.get("u_size"),
                dev.get("dev_type", ""), dev.get("model", ""), dev.get("vendor", ""),
                float(dev.get("power_w") or 0), float(dev.get("weight_kg") or 0),
            )

        def reservation_signature(res: dict[str, Any]) -> tuple:
            return (
                res.get("u_start"), res.get("u_size"), res.get("label", ""),
                res.get("project", ""), res.get("owner", ""),
            )

        left_devices = {device_signature(dev): dev for dev in left_layout["devices"]}
        right_devices = {device_signature(dev): dev for dev in right_layout["devices"]}
        left_reservations = {reservation_signature(res): res for res in left_layout["reservations"]}
        right_reservations = {reservation_signature(res): res for res in right_layout["reservations"]}
        changes: list[dict[str, str]] = []
        for key in sorted(set(left_devices) - set(right_devices), key=lambda item: (item[1] or 999, item[0])):
            changes.append({"kind": "device", "side": "left_only", "name": key[0],
                            "u": f"{key[1]}-{(key[1] or 0) + key[2] - 1}U"})
        for key in sorted(set(right_devices) - set(left_devices), key=lambda item: (item[1] or 999, item[0])):
            changes.append({"kind": "device", "side": "right_only", "name": key[0],
                            "u": f"{key[1]}-{(key[1] or 0) + key[2] - 1}U"})
        for key in sorted(set(left_reservations) - set(right_reservations), key=lambda item: item[0] or 0):
            changes.append({"kind": "reservation", "side": "left_only", "name": key[2],
                            "u": f"{key[0]}-{key[0] + key[1] - 1}U"})
        for key in sorted(set(right_reservations) - set(left_reservations), key=lambda item: item[0] or 0):
            changes.append({"kind": "reservation", "side": "right_only", "name": key[2],
                            "u": f"{key[0]}-{key[0] + key[1] - 1}U"})
        return {
            "left": left_layout,
            "right": right_layout,
            "identical": not changes,
            "changes": changes,
        }

    # ---------- devices ----------

    def list_devices(self, cabinet_id: Optional[int] = None) -> list[dict]:
        sql = "SELECT * FROM device"
        params: list = []
        if cabinet_id is not None:
            sql += " WHERE cabinet_id=?"
            params.append(cabinet_id)
        sql += " ORDER BY cabinet_id, u_start"
        return self.query(sql, tuple(params))

    def create_device(self, cabinet_id: Optional[int], data: DeviceIn) -> dict:
        if cabinet_id is not None:
            check = self.check_placement(cabinet_id, data.u_start, data.u_size)
            if not check["ok"]:
                raise ValueError(check.get("message", "U 位冲突"))
        did = self.execute(
            "INSERT INTO device(cabinet_id, name, u_start, u_size, dev_type, status, model, vendor, "
            "mgmt_ip, power_w, weight_kg, remark) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (cabinet_id, data.name, data.u_start, data.u_size, data.dev_type, data.status,
             data.model, data.vendor, data.mgmt_ip, data.power_w, data.weight_kg, data.remark),
        )
        return self.query_one("SELECT * FROM device WHERE id=?", (did,))

    def update_device(self, device_id: int, data: DeviceIn, cabinet_id: Optional[int]) -> dict:
        old = self.query_one("SELECT cabinet_id FROM device WHERE id=?", (device_id,))
        if old is None:
            raise ValueError("设备不存在")
        target = cabinet_id if cabinet_id is not None else old["cabinet_id"]
        if target is not None:
            check = self.check_placement(target, data.u_start, data.u_size, "device", device_id)
            if not check["ok"]:
                raise ValueError(check.get("message", "U 位冲突"))
        self.execute(
            "UPDATE device SET cabinet_id=?, name=?, u_start=?, u_size=?, dev_type=?, status=?, "
            "model=?, vendor=?, mgmt_ip=?, power_w=?, weight_kg=?, remark=?, "
            "updated_at=datetime('now','localtime') WHERE id=?",
            (target, data.name, data.u_start, data.u_size, data.dev_type, data.status,
             data.model, data.vendor, data.mgmt_ip, data.power_w, data.weight_kg, data.remark, device_id),
        )
        return self.query_one("SELECT * FROM device WHERE id=?", (device_id,))

    def delete_device(self, device_id: int) -> None:
        self.execute("DELETE FROM device WHERE id=?", (device_id,))

    # ---------- reservations ----------

    def list_reservations(self, cabinet_id: Optional[int] = None) -> list[dict]:
        sql = "SELECT * FROM reservation"
        params: list = []
        if cabinet_id is not None:
            sql += " WHERE cabinet_id=?"
            params.append(cabinet_id)
        sql += " ORDER BY cabinet_id, u_start"
        return self.query(sql, tuple(params))

    def create_reservation(self, cabinet_id: int, data: ReservationIn) -> dict:
        check = self.check_placement(cabinet_id, data.u_start, data.u_size)
        if not check["ok"]:
            raise ValueError(check.get("message", "U 位冲突"))
        rid = self.execute(
            "INSERT INTO reservation(cabinet_id, u_start, u_size, label, project, owner, remark) "
            "VALUES(?,?,?,?,?,?,?)",
            (cabinet_id, data.u_start, data.u_size, data.label, data.project, data.owner, data.remark),
        )
        return self.query_one("SELECT * FROM reservation WHERE id=?", (rid,))

    def delete_reservation(self, reservation_id: int) -> None:
        self.execute("DELETE FROM reservation WHERE id=?", (reservation_id,))

    # ---------- layout & capacity ----------

    def cabinet_layout(self, cabinet_id: int) -> dict[str, Any]:
        cab = self.query_one("SELECT * FROM cabinet WHERE id=?", (cabinet_id,))
        if cab is None:
            raise ValueError("机柜不存在")
        return {
            "cabinet": cab,
            "devices": self.list_devices(cabinet_id),
            "reservations": self.list_reservations(cabinet_id),
            "free_slots": self.free_slots(cabinet_id),
        }

    def capacity(self) -> list[dict[str, Any]]:
        cabinets = self.query(
            "SELECT c.*, r.name AS room_name FROM cabinet c LEFT JOIN room r ON r.id=c.room_id "
            "ORDER BY r.name, c.name"
        )
        result = []
        for cab in cabinets:
            dev = self.query_one(
                "SELECT COUNT(*) AS dev_count, COALESCE(SUM(u_size),0) AS u_used, "
                "COALESCE(SUM(power_w),0) AS power_used, COALESCE(SUM(weight_kg),0) AS weight_used "
                "FROM device WHERE cabinet_id=? AND u_start IS NOT NULL AND status<>'已下架'",
                (cab["id"],),
            ) or {}
            reserved = self.scalar(
                "SELECT COALESCE(SUM(u_size),0) FROM reservation WHERE cabinet_id=?", (cab["id"],), 0
            )
            u_total = cab["u_total"]
            u_used = dev.get("u_used", 0)
            result.append({
                "cabinet_id": cab["id"],
                "room_name": cab["room_name"] or "",
                "cabinet_name": cab["name"],
                "u_total": u_total,
                "u_used": u_used,
                "u_reserved": reserved,
                "u_free": u_total - u_used - reserved,
                "u_pct": round(u_used / u_total * 100, 1) if u_total else 0,
                "power_limit_w": cab["power_limit_w"],
                "power_used": dev.get("power_used", 0),
                "power_pct": (
                    round(dev.get("power_used", 0) / cab["power_limit_w"] * 100, 1)
                    if cab.get("power_limit_w") else None
                ),
                "weight_limit_kg": cab["weight_limit_kg"],
                "weight_used": dev.get("weight_used", 0),
                "weight_pct": (
                    round(dev.get("weight_used", 0) / cab["weight_limit_kg"] * 100, 1)
                    if cab.get("weight_limit_kg") else None
                ),
                "dev_count": dev.get("dev_count", 0),
            })
        return result


store = CabinetStore()
