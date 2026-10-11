import json
import subprocess
import sys


def run(*args):
    return subprocess.run([sys.executable, "-m", "infrasentinel.cli", *args], capture_output=True, text=True, check=False)


def loaded(tmp_path):
    db = tmp_path / "t.db"
    assert run("sample_data/auth.log", "--database", str(db)).returncode == 0
    return str(db)


def test_filters_combine_and_json_has_no_raw_lines(tmp_path):
    db = loaded(tmp_path)
    out = run("--search", "--ip", "203.0.113.7", "--outcome", "failed", "--json", "--database", db)
    assert out.returncode == 0, out.stderr
    rows = json.loads(out.stdout)
    assert rows and all(r["source_ip"] == "203.0.113.7" and r["outcome"] == "failed" for r in rows)
    assert all("raw_line" not in r for r in rows)
    assert "port " not in out.stdout


def test_limit_and_text_output(tmp_path):
    db = loaded(tmp_path)
    out = run("--search", "--limit", "2", "--database", db)
    assert out.stdout.strip().splitlines()[-1] == "2 matching events"


def test_filter_values_are_not_sql_injectable(tmp_path):
    db = loaded(tmp_path)
    out = run("--search", "--user", "x' OR '1'='1", "--database", db)
    assert out.returncode == 0 and "0 matching events" in out.stdout


def test_anonymize_masks_ips_in_search(tmp_path):
    db = loaded(tmp_path)
    out = run("--search", "--ip", "192.0.2.44", "--anonymize", "--database", db)
    assert "192.0.2.44" not in out.stdout and "ip-001" in out.stdout


def test_search_never_creates_db_or_mixes_modes(tmp_path):
    missing = tmp_path / "none.db"
    assert run("--search", "--database", str(missing)).returncode != 0
    assert not missing.exists()
    mixed = run("--search", "--purge", "--yes", "--database", loaded(tmp_path))
    assert mixed.returncode != 0 and "cannot be combined" in mixed.stderr
    assert run("--search", "--limit", "0", "--database", loaded(tmp_path)).returncode != 0
