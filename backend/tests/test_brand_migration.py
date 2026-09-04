import sqlite3

from app.platform_security import _migrate_legacy_data_dir


def test_packet_lens_data_is_copied_to_nocslate_without_removing_source(tmp_path):
    legacy = tmp_path / "PacketLens"
    legacy.mkdir()
    with sqlite3.connect(legacy / "ops.db") as connection:
        connection.execute("CREATE TABLE sample (value TEXT NOT NULL)")
        connection.execute("INSERT INTO sample VALUES ('kept')")
        connection.execute("CREATE TABLE knowledge_document (id INTEGER PRIMARY KEY, file_path TEXT NOT NULL)")
        connection.execute(
            "INSERT INTO knowledge_document VALUES (1, ?)",
            (str(legacy / "knowledge" / "note.md"),),
        )
    (legacy / "knowledge").mkdir()
    (legacy / "knowledge" / "note.md").write_text("legacy note", encoding="utf-8")

    target = tmp_path / "NOCSlate"
    migrated = _migrate_legacy_data_dir(tmp_path, target)

    assert migrated == target
    assert legacy.is_dir()
    assert (target / "knowledge" / "note.md").read_text(encoding="utf-8") == "legacy note"
    with sqlite3.connect(target / "ops.db") as connection:
        assert connection.execute("SELECT value FROM sample").fetchone()[0] == "kept"
        assert connection.execute("SELECT file_path FROM knowledge_document").fetchone()[0] == str(
            target / "knowledge" / "note.md"
        )


def test_existing_nocslate_data_is_never_overwritten(tmp_path):
    legacy = tmp_path / "PacketLens"
    legacy.mkdir()
    (legacy / "known_hosts").write_text("old", encoding="utf-8")
    target = tmp_path / "NOCSlate"
    target.mkdir()
    (target / "known_hosts").write_text("current", encoding="utf-8")

    assert _migrate_legacy_data_dir(tmp_path, target) == target
    assert (target / "known_hosts").read_text(encoding="utf-8") == "current"
