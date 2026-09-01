"""Cabinet management: rooms, cabinets, devices, U-position occupancy and capacity."""

from __future__ import annotations

import sqlite3
import sys
import threading
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
