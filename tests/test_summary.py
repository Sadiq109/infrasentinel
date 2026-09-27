import json
import sys

import pytest

from infrasentinel.cli import main
from infrasentinel.models import AuthEvent
from infrasentinel.storage import connect, save_events
from infrasentinel.summary import summarize


def ev(outcome, ip, number):
    return AuthEvent("Sep 20 10:15:01", "web01", "sshd", outcome,
                     "root", ip, f"synthetic log {number}")


def test_empty_summary():
    assert summarize(connect(":memory:")) == {
        "total_events": 0,
        "outcomes": {"accepted": 0, "failed": 0, "invalid_user": 0},
        "distinct_sources": 0,
        "top_failed_sources": [],
    }


def test_counts_and_orders_failed_sources_without_raw_lines():
    db = connect(":memory:")
    save_events(db, [ev("failed", "192.0.2.1", 1),
                     ev("invalid_user", "192.0.2.1", 2),
                     ev("failed", "192.0.2.2", 3),
                     ev("accepted", "192.0.2.2", 4),
                     ev("failed", None, 5)])
    result = summarize(db)
    assert result["total_events"] == 5
    assert result["outcomes"] == {"accepted": 1, "failed": 3, "invalid_user": 1}
    assert result["distinct_sources"] == 2
    assert result["top_failed_sources"] == [
        {"source_ip": "192.0.2.1", "attempts": 2},
        {"source_ip": "192.0.2.2", "attempts": 1},
    ]
    assert "synthetic log" not in str(result)


def test_summary_cli_json_does_not_import(monkeypatch, tmp_path, capsys):
    path = tmp_path / "auth.db"
    db = connect(path)
    save_events(db, [ev("failed", "192.0.2.1", 1)])
    db.close()
    monkeypatch.setattr(sys, "argv", ["infrasentinel", "--summary",
                                          "--database", str(path), "--json"])
    assert main() == 0
    assert json.loads(capsys.readouterr().out)["total_events"] == 1
    assert connect(path).execute("SELECT COUNT(*) FROM auth_events").fetchone()[0] == 1


def test_summary_refuses_missing_database_and_logfile(monkeypatch, tmp_path):
    path = tmp_path / "missing.db"
    monkeypatch.setattr(sys, "argv", ["infrasentinel", "--summary", "--database", str(path)])
    with pytest.raises(SystemExit, match="Database does not exist"):
        main()
    assert not path.exists()
    monkeypatch.setattr(sys, "argv", ["infrasentinel"])
    with pytest.raises(SystemExit, match="A logfile is required"):
        main()


def test_top_sources_limit_and_tie_order():
    db = connect(":memory:")
    save_events(db, [ev("failed", f"192.0.2.{i}", i) for i in range(1, 8)])
    assert [row["source_ip"] for row in summarize(db)["top_failed_sources"]] == [
        f"192.0.2.{i}" for i in range(1, 6)
    ]


def test_summary_cli_human_output(monkeypatch, tmp_path, capsys):
    path = tmp_path / "auth.db"
    db = connect(path)
    save_events(db, [ev("invalid_user", "192.0.2.9", 1)])
    db.close()
    monkeypatch.setattr(sys, "argv", ["infrasentinel", "--summary", "--database", str(path)])
    assert main() == 0
    output = capsys.readouterr().out
    assert "Stored events: 1" in output
    assert "invalid_user: 1" in output
    assert "192.0.2.9: 1" in output
    assert "synthetic log" not in output


def test_summary_rejects_logfile(monkeypatch, tmp_path):
    path = tmp_path / "auth.db"
    connect(path).close()
    monkeypatch.setattr(sys, "argv", ["infrasentinel", "sample_data/auth.log",
                                          "--summary", "--database", str(path)])
    with pytest.raises(SystemExit, match="does not accept a logfile"):
        main()
