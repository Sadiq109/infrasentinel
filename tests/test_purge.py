import sqlite3
import subprocess
import sys


def run(*args):
    return subprocess.run([sys.executable, "-m", "infrasentinel.cli", *args], capture_output=True, text=True, check=False)


def count(db):
    with sqlite3.connect(db) as c:
        return c.execute("SELECT COUNT(*) FROM auth_events").fetchone()[0]


def test_purge_requires_yes_and_keeps_data(tmp_path):
    db = tmp_path / "t.db"
    assert run("sample_data/auth.log", "--database", str(db)).returncode == 0
    before = count(db)
    result = run("--purge", "--database", str(db))
    assert result.returncode != 0 and "--yes" in result.stderr
    assert count(db) == before > 0


def test_purge_deletes_all_events_and_removes_text_from_file(tmp_path):
    db = tmp_path / "t.db"
    run("sample_data/auth.log", "--database", str(db))
    assert b"203.0.113.7" in db.read_bytes()
    result = run("--purge", "--yes", "--database", str(db))
    assert result.returncode == 0, result.stderr
    assert "Deleted 12 stored events" in result.stdout
    assert count(db) == 0
    assert b"203.0.113.7" not in db.read_bytes()


def test_purge_never_creates_a_database_or_mixes_modes(tmp_path):
    missing = tmp_path / "none.db"
    assert run("--purge", "--yes", "--database", str(missing)).returncode != 0
    assert not missing.exists()
    mixed = run("sample_data/auth.log", "--purge", "--yes", "--database", str(tmp_path / "x.db"))
    assert mixed.returncode != 0 and "cannot be combined" in mixed.stderr
