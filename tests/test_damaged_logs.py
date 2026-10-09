import subprocess
import sys

GOOD = "Sep 20 10:15:01 web01 sshd[921]: Failed password for invalid user admin from 203.0.113.7 port 51122 ssh2\n"


def run(*args):
    return subprocess.run([sys.executable, "-m", "infrasentinel.cli", *args], capture_output=True, text=True, check=False)


def test_invalid_bytes_and_garbage_lines_do_not_abort_import(tmp_path):
    log = tmp_path / "auth.log"
    log.write_bytes(
        b"\xff\xfe\x00garbage\n"
        + b"Sep 20 10:15:00 web01 sshd[1]: Failed password for \xc3\x28 from 203.0.113.7 port 1 ssh2\n"
        + GOOD.encode()
        + b"truncated line with no newline"
    )
    result = run(str(log), "--database", str(tmp_path / "t.db"))
    assert result.returncode == 0, result.stderr
    assert "Traceback" not in result.stderr
    assert "Imported 2 new events" in result.stdout


def test_missing_log_file_gives_short_error_and_no_database(tmp_path):
    db = tmp_path / "t.db"
    result = run(str(tmp_path / "nope.log"), "--database", str(db))
    assert result.returncode != 0
    assert "Cannot read log file" in result.stderr
    assert "Traceback" not in result.stderr


def test_empty_and_rotated_duplicate_imports_are_safe(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    assert "Imported 0 new events" in run(str(log), "--database", str(tmp_path / "t.db")).stdout
    log.write_text(GOOD, encoding="utf-8")
    assert "Imported 1 new events" in run(str(log), "--database", str(tmp_path / "t.db")).stdout
    # A rotated copy repeating the same line adds nothing.
    assert "Imported 0 new events" in run(str(log), "--database", str(tmp_path / "t.db")).stdout
