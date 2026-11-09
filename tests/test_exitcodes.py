from infrasentinel.cli import main as cli_main


def run_cli(argv, monkeypatch):
    monkeypatch.setattr("sys.argv", ["infrasentinel", *argv])
    return cli_main()


def test_default_exit_is_zero_even_with_findings(tmp_path, monkeypatch, capsys):
    code = run_cli(
        ["sample_data/auth.log", "--database", str(tmp_path / "t.db"), "--threshold", "5"],
        monkeypatch,
    )
    assert code == 0
    assert "AUTH-BRUTE-FORCE" in capsys.readouterr().out


def test_fail_on_findings_exits_one_when_findings_exist(tmp_path, monkeypatch):
    code = run_cli(
        ["sample_data/auth.log", "--database", str(tmp_path / "t.db"), "--threshold", "5", "--fail-on-findings"],
        monkeypatch,
    )
    assert code == 1


def test_fail_on_findings_exits_zero_without_findings(tmp_path, monkeypatch):
    code = run_cli(
        ["sample_data/auth.log", "--database", str(tmp_path / "t.db"), "--threshold", "50", "--fail-on-findings"],
        monkeypatch,
    )
    assert code == 0


def test_fail_on_findings_still_reports_findings(tmp_path, monkeypatch, capsys):
    run_cli(
        ["sample_data/auth.log", "--database", str(tmp_path / "t.db"), "--threshold", "5", "--fail-on-findings", "--json"],
        monkeypatch,
    )
    out = capsys.readouterr().out
    assert '"findings"' in out
    assert "AUTH-BRUTE-FORCE" in out
