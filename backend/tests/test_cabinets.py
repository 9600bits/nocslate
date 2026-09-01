import pytest

from app.cabinets import CabinetStore, CabinetIn, DeviceIn, ReservationIn, RoomIn
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
