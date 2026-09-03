import sqlite3

import pytest

from app.cabinets import CabinetStore, CabinetIn, DeviceIn, ReservationIn, RoomIn, db_path
from app.cabinets import TemplateApplyIn, TemplateIn


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr("app.cabinets.db_path", lambda: tmp_path / "cabinets.db")
    return CabinetStore()


def test_room_cabinet_device_flow(store):
    room = store.create_room(RoomIn(name="A1", code="BJ-A1"))
    cab = store.create_cabinet(room["id"], CabinetIn(name="C01", u_total=12, power_limit_w=3700))
    dev = store.create_device(cab["id"], DeviceIn(name="sw-01", u_start=1, u_size=2, dev_type="交换机"))
    assert dev["u_start"] == 1

    check = store.check_placement(cab["id"], 2, 1)
    assert not check["ok"]

    layout = store.cabinet_layout(cab["id"])
    assert layout["free_slots"][0]["u_start"] == 3


def test_reservation_conflict(store):
    room = store.create_room(RoomIn(name="B1"))
    cab = store.create_cabinet(room["id"], CabinetIn(name="C01", u_total=8))
    store.create_device(cab["id"], DeviceIn(name="srv", u_start=4, u_size=2))
    with pytest.raises(ValueError, match="U 位冲突"):
        store.create_reservation(cab["id"], ReservationIn(u_start=5, u_size=1))


def test_capacity(store):
    room = store.create_room(RoomIn(name="C1"))
    cab = store.create_cabinet(room["id"], CabinetIn(name="C01", u_total=10, power_limit_w=1000))
    store.create_device(cab["id"], DeviceIn(name="d", u_start=1, u_size=2, power_w=300))
    rows = store.capacity()
    assert rows[0]["u_pct"] == 20.0
    assert rows[0]["power_pct"] == 30.0


def test_capacity_includes_reservations(store):
    room = store.create_room(RoomIn(name="容量测试"))
    cab = store.create_cabinet(room["id"], CabinetIn(name="C01", u_total=10))
    store.create_device(cab["id"], DeviceIn(name="设备", u_start=1, u_size=2))
    store.create_reservation(cab["id"], ReservationIn(u_start=5, u_size=3))

    row = store.capacity()[0]
    assert row["u_used"] == 2
    assert row["u_reserved"] == 3
    assert row["u_free"] == 5
    assert row["u_pct"] == 50.0


def test_duplicate_cabinet(store):
    room = store.create_room(RoomIn(name="D1"))
    cab = store.create_cabinet(room["id"], CabinetIn(name="C01", u_total=10, power_limit_w=2000))
    store.create_device(cab["id"], DeviceIn(name="sw", u_start=1, u_size=2, dev_type="交换机", power_w=100))
    store.create_device(cab["id"], DeviceIn(name="srv", u_start=5, u_size=4, dev_type="服务器", mgmt_ip="10.0.0.1"))
    store.create_reservation(cab["id"], ReservationIn(u_start=9, u_size=2, label="扩容"))

    dup = store.duplicate_cabinet(cab["id"], "C01-copy")
    assert dup["name"] == "C01-copy"
    assert dup["u_total"] == 10

    devs = store.list_devices(dup["id"])
    assert len(devs) == 2
    assert devs[0]["name"] == "sw" and devs[0]["u_start"] == 1
    assert devs[1]["name"] == "srv" and devs[1]["status"] == "备用"

    check = store.check_placement(dup["id"], 1, 1)
    assert not check["ok"]  # copied device occupies same U

    store.create_cabinet(room["id"], CabinetIn(name="C02"))
    with pytest.raises(ValueError, match="已存在"):
        store.duplicate_cabinet(cab["id"], "C02")


def test_template_batch_names(store):
    assert store._template_names("C-07", 3, 9) == ["C-09", "C-10", "C-11"]
    assert store._template_names("冗余柜", 2, 3) == ["冗余柜-03", "冗余柜-04"]


def test_template_apply_clears_mgmt_ip(store):
    room = store.create_room(RoomIn(name="T1"))
    cab = store.create_cabinet(room["id"], CabinetIn(name="C01", u_total=10))
    store.create_device(cab["id"], DeviceIn(
        name="sw", u_start=1, u_size=2, dev_type="交换机", mgmt_ip="10.0.0.1",
    ))
    template = store.save_template(cab["id"], TemplateIn(name="标准接入柜"))

    target_room = store.create_room(RoomIn(name="T2"))
    created = store.apply_template(template["id"], TemplateApplyIn(
        room_id=target_room["id"], base_name="B-01", count=2,
    ))

    assert [item["name"] for item in created] == ["B-01", "B-02"]
    devices = store.list_devices(created[0]["id"])
    assert len(devices) == 1
    assert devices[0]["mgmt_ip"] == ""
    assert devices[0]["u_start"] == 1

    with pytest.raises(ValueError, match="已存在"):
        store.apply_template(template["id"], TemplateApplyIn(
            room_id=target_room["id"], base_name="B-01", count=1,
        ))


def test_template_apply_is_atomic_when_later_name_exists(store):
    source_room = store.create_room(RoomIn(name="模板源"))
    source = store.create_cabinet(source_room["id"], CabinetIn(name="SRC", u_total=10))
    template = store.save_template(source["id"], TemplateIn(name="原子模板"))
    target = store.create_room(RoomIn(name="模板目标"))
    store.create_cabinet(target["id"], CabinetIn(name="B-02"))

    with pytest.raises(ValueError, match="B-02"):
        store.apply_template(template["id"], TemplateApplyIn(
            room_id=target["id"], base_name="B-01", count=2,
        ))

    assert [cab["name"] for cab in store.list_cabinets(target["id"])] == ["B-02"]


def test_template_apply_rolls_back_on_write_failure(store, monkeypatch):
    source_room = store.create_room(RoomIn(name="失败模板源"))
    source = store.create_cabinet(source_room["id"], CabinetIn(name="SRC"))
    store.create_device(source["id"], DeviceIn(name="模板设备", u_start=1))
    template = store.save_template(source["id"], TemplateIn(name="失败回滚模板"))
    target = store.create_room(RoomIn(name="失败模板目标"))
    original_execute = store.execute

    def fail_device_insert(sql, params=()):
        if sql.startswith("INSERT INTO device"):
            raise sqlite3.OperationalError("simulated write failure")
        return original_execute(sql, params)

    monkeypatch.setattr(store, "execute", fail_device_insert)
    with pytest.raises(sqlite3.OperationalError, match="simulated"):
        store.apply_template(template["id"], TemplateApplyIn(
            room_id=target["id"], base_name="ROLLBACK-01", count=1,
        ))

    assert store.list_cabinets(target["id"]) == []


def test_delete_cabinet_moves_devices_to_unracked(store):
    room = store.create_room(RoomIn(name="删除机柜"))
    cab = store.create_cabinet(room["id"], CabinetIn(name="C01"))
    dev = store.create_device(cab["id"], DeviceIn(name="保留设备", u_start=8, u_size=2))

    store.delete_cabinet(cab["id"])

    kept = store.query_one("SELECT * FROM device WHERE id=?", (dev["id"],))
    assert kept is not None
    assert kept["cabinet_id"] is None
    assert kept["u_start"] is None
    assert [item["id"] for item in store.list_devices(unracked_only=True)] == [dev["id"]]


def test_delete_room_moves_devices_to_unracked(store):
    room = store.create_room(RoomIn(name="删除机房"))
    first = store.create_cabinet(room["id"], CabinetIn(name="C01"))
    second = store.create_cabinet(room["id"], CabinetIn(name="C02"))
    ids = {
        store.create_device(first["id"], DeviceIn(name="D1", u_start=1))["id"],
        store.create_device(second["id"], DeviceIn(name="D2", u_start=2))["id"],
    }

    store.delete_room(room["id"])

    unracked = store.list_devices(unracked_only=True)
    assert {item["id"] for item in unracked} == ids
    assert all(item["cabinet_id"] is None and item["u_start"] is None for item in unracked)


def test_cabinet_cannot_shrink_below_device_or_reservation(store):
    room = store.create_room(RoomIn(name="缩柜测试"))
    cab = store.create_cabinet(room["id"], CabinetIn(name="设备高位", u_total=20))
    store.create_device(cab["id"], DeviceIn(name="高位设备", u_start=17, u_size=2))
    with pytest.raises(ValueError, match="18U"):
        store.update_cabinet(cab["id"], CabinetIn(name="设备高位", u_total=17))

    reserved_cab = store.create_cabinet(room["id"], CabinetIn(name="预留高位", u_total=20))
    store.create_reservation(reserved_cab["id"], ReservationIn(u_start=19, u_size=2))
    with pytest.raises(ValueError, match="20U"):
        store.update_cabinet(reserved_cab["id"], CabinetIn(name="预留高位", u_total=19))


def test_place_and_unrack_device(store):
    room = store.create_room(RoomIn(name="重新上架"))
    cab = store.create_cabinet(room["id"], CabinetIn(name="C01", u_total=10))
    blocker = store.create_device(cab["id"], DeviceIn(name="占位设备", u_start=1, u_size=2))
    pending = store.create_device(None, DeviceIn(name="待上架", u_start=9, u_size=2))
    assert pending["u_start"] is None

    with pytest.raises(ValueError, match="必须指定"):
        store.place_device(pending["id"], cab["id"], None)
    with pytest.raises(ValueError, match="U 位冲突"):
        store.place_device(pending["id"], cab["id"], 2)

    placed = store.place_device(pending["id"], cab["id"], 3)
    assert placed["cabinet_id"] == cab["id"] and placed["u_start"] == 3
    assert blocker["id"] != placed["id"]

    unracked = store.place_device(pending["id"], None, None)
    assert unracked["cabinet_id"] is None and unracked["u_start"] is None


def test_retired_device_does_not_occupy_u_and_cannot_be_placed(store):
    room = store.create_room(RoomIn(name="下架设备"))
    cab = store.create_cabinet(room["id"], CabinetIn(name="C01", u_total=10))
    retired = store.create_device(cab["id"], DeviceIn(
        name="旧设备", u_start=1, u_size=2, status="已下架",
    ))
    active = store.create_device(cab["id"], DeviceIn(name="新设备", u_start=1, u_size=2))
    assert active["u_start"] == retired["u_start"]
    assert store.capacity()[0]["u_used"] == 2

    store.place_device(retired["id"], None, None)
    with pytest.raises(ValueError, match="请先改为"):
        store.place_device(retired["id"], cab["id"], 5)


def test_migration_clears_orphan_u_start(store):
    store.execute(
        "INSERT INTO device(cabinet_id,name,u_start,u_size) VALUES(NULL,?,?,?)",
        ("旧孤儿设备", 20, 1),
    )
    store.close()

    reopened = CabinetStore()
    try:
        device = reopened.query_one("SELECT * FROM device WHERE name=?", ("旧孤儿设备",))
        assert device is not None
        assert device["cabinet_id"] is None and device["u_start"] is None
    finally:
        reopened.close()


def test_frozen_db_path_migrates_legacy_database(tmp_path, monkeypatch):
    exe_dir = tmp_path / "release"
    exe_dir.mkdir()
    executable = exe_dir / "PacketLens.exe"
    executable.touch()
    legacy = exe_dir / "cabinets.db"
    conn = sqlite3.connect(legacy)
    conn.execute("CREATE TABLE marker(value TEXT)")
    conn.execute("INSERT INTO marker(value) VALUES('legacy')")
    conn.commit()
    conn.close()

    appdata = tmp_path / "AppData" / "Roaming"
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.setattr("app.cabinets.sys.frozen", True, raising=False)
    monkeypatch.setattr("app.cabinets.sys.executable", str(executable))

    migrated = db_path()
    assert migrated == appdata / "PacketLens" / "cabinets.db"
    copied = sqlite3.connect(migrated)
    try:
        assert copied.execute("SELECT value FROM marker").fetchone()[0] == "legacy"
    finally:
        copied.close()


def test_compare_cabinets_identical_and_changed(store):
    room = store.create_room(RoomIn(name="AB"))
    cab = store.create_cabinet(room["id"], CabinetIn(name="C01", u_total=10))
    store.create_device(cab["id"], DeviceIn(
        name="sw", u_start=1, u_size=2, dev_type="交换机", mgmt_ip="10.0.0.1",
    ))
    store.create_reservation(cab["id"], ReservationIn(u_start=9, u_size=2, label="扩容"))

    replica = store.duplicate_cabinet(cab["id"], "C01-B")
    result = store.compare_cabinets(cab["id"], replica["id"])
    assert result["identical"] is True
    assert result["changes"] == []

    store.create_device(replica["id"], DeviceIn(
        name="extra", u_start=4, u_size=1, dev_type="服务器",
    ))
    changed = store.compare_cabinets(cab["id"], replica["id"])
    assert changed["identical"] is False
    assert len(changed["changes"]) == 1
    assert changed["changes"][0]["side"] == "right_only"
    assert changed["changes"][0]["name"] == "extra"
