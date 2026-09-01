import pytest

from app.cabinets import CabinetStore, CabinetIn, DeviceIn, ReservationIn, RoomIn


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
