from infrasentinel.cli import main as cli_main
from infrasentinel.parser import parse_line

ISO_FAILURE = (
    "2026-11-07T13:23:{sec:02d}-0600 web01 sshd[431]: "
    "Failed password for invalid user admin from 198.51.100.23 port 55122 ssh2"
)


def test_parses_short_iso_line():
    event = parse_line(ISO_FAILURE.format(sec=1))
    assert event is not None
    assert event.outcome == "failed"
    assert event.username == "admin"
    assert event.source_ip == "198.51.100.23"
    assert event.occurred_at == "2026-11-07T13:23:01-06:00"


def test_parses_short_iso_precise_fractional_seconds():
    event = parse_line(
        "2026-11-07T13:23:01.483215-0600 web01 sshd[431]: "
        "Failed password for root from 198.51.100.23 port 55122 ssh2"
    )
    assert event is not None
    assert event.occurred_at == "2026-11-07T13:23:01.483215-06:00"


def test_iso_offset_with_colon_and_z():
    event = parse_line(ISO_FAILURE.format(sec=2).replace("-0600", "-06:00"))
    assert event is not None
    assert event.occurred_at == "2026-11-07T13:23:02-06:00"
    zulu = parse_line(ISO_FAILURE.format(sec=3).replace("-0600", "Z"))
    assert zulu is not None
    assert zulu.occurred_at == "2026-11-07T13:23:03+00:00"


def test_iso_line_ignores_year_and_tz_options():
    event = parse_line(ISO_FAILURE.format(sec=4), year=1999)
    assert event is not None
    assert event.occurred_at.startswith("2026-11-07")


def test_invalid_iso_date_is_skipped():
    assert (
        parse_line(
            "2026-13-40T13:23:01-0600 web01 sshd[431]: "
            "Failed password for root from 198.51.100.23 port 55122 ssh2"
        )
        is None
    )


def test_non_sshd_iso_lines_are_ignored():
    assert (
        parse_line("2026-11-07T13:23:01-0600 web01 cron[9]: pam_unix(cron:session): session opened")
        is None
    )


def test_cli_imports_journalctl_log_and_detects_brute_force(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["infrasentinel", "sample_data/auth-journalctl.log", "--database", str(tmp_path / "t.db"), "--threshold", "5"],
    )
    assert cli_main() == 0
    out = capsys.readouterr().out
    assert "Imported 5 new events" in out
    assert "BRUTE-FORCE" in out
    assert "198.51.100.23" in out
