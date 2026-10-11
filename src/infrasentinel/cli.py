import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .anonymize import IpAnonymizer
from .detectors import (
    detect_brute_force,
    detect_brute_force_window,
    detect_success_after_failures,
)
from .export import write_findings
from .parser import parse_lines
from .storage import connect, purge_events, save_events, search_events
from .summary import summarize


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="infrasentinel",
        description="Parse Linux authentication logs and surface suspicious activity.",
    )
    parser.add_argument("logfile", type=Path, nargs="?", help="Path to a syslog/auth.log file")
    parser.add_argument("--database", type=Path, default=Path("infrasentinel.db"))
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--summary", action="store_true", help="Summarize stored events without importing a log")
    parser.add_argument("--export", type=Path, help="Write findings to this file (never overwrites an existing file)")
    parser.add_argument("--window-seconds", type=int, help="Also flag threshold failures inside this many seconds (needs --year)")
    parser.add_argument("--search", action="store_true", help="List stored events matching --ip, --user and/or --outcome")
    parser.add_argument("--ip", help="With --search: exact source IP")
    parser.add_argument("--user", help="With --search: exact username")
    parser.add_argument("--outcome", choices=("failed", "accepted", "invalid_user"), help="With --search: event outcome")
    parser.add_argument("--limit", type=int, default=50, help="With --search: maximum rows (default 50)")
    parser.add_argument("--purge", action="store_true", help="Delete all stored events from the database (needs --yes)")
    parser.add_argument("--yes", action="store_true", help="Confirm a destructive action such as --purge")
    parser.add_argument("--year", type=int, help="Year of the log (syslog timestamps have none); stores ISO timestamps")
    parser.add_argument("--anonymize", action="store_true", help="Replace source IPs with ip-001 style labels in output and exports")
    parser.add_argument("--export-format", choices=("csv", "jsonl"), default="csv")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.year is not None and not 1970 <= args.year <= 9999:
        raise SystemExit("--year must be between 1970 and 9999")
    if args.window_seconds is not None and args.window_seconds < 1:
        raise SystemExit("--window-seconds must be at least 1")
    if args.window_seconds is not None and args.year is None:
        raise SystemExit("--window-seconds needs --year so events have full timestamps")
    if args.threshold < 1:
        raise SystemExit("--threshold must be at least 1")
    if args.search:
        if args.logfile is not None or args.purge or args.summary or args.export is not None:
            raise SystemExit("--search cannot be combined with a logfile, --purge, --summary or --export")
        if args.limit < 1:
            raise SystemExit("--limit must be at least 1")
        if not args.database.is_file():
            raise SystemExit(f"Database does not exist: {args.database}")
        connection = connect(args.database)
        rows = search_events(connection, args.ip, args.user, args.outcome, args.limit)
        connection.close()
        if args.anonymize:
            anonymizer = IpAnonymizer()
            for row in rows:
                if row["source_ip"] is not None:
                    row["source_ip"] = anonymizer.label(row["source_ip"])
        if args.as_json:
            print(json.dumps(rows, indent=2))
        else:
            for row in rows:
                print(f"{row['occurred_at']} {row['hostname']} {row['outcome']} user={row['username']} ip={row['source_ip']}")
            print(f"{len(rows)} matching events")
        return 0
    if args.purge:
        if args.logfile is not None or args.summary or args.export is not None:
            raise SystemExit("--purge cannot be combined with a logfile, --summary or --export")
        if not args.yes:
            raise SystemExit("--purge deletes all stored events; add --yes to confirm")
        if not args.database.is_file():
            raise SystemExit(f"Database does not exist: {args.database}")
        connection = connect(args.database)
        removed = purge_events(connection)
        connection.close()
        print(f"Deleted {removed} stored events from {args.database}")
        return 0
    if args.summary:
        if args.logfile is not None:
            raise SystemExit("--summary does not accept a logfile")
        if not args.database.is_file():
            raise SystemExit(f"Database does not exist: {args.database}")
        connection = connect(args.database)
        report = summarize(connection)
        connection.close()
        if args.as_json:
            print(json.dumps(report, indent=2))
        else:
            print(f"Stored events: {report['total_events']}")
            print(f"Distinct source IPs: {report['distinct_sources']}")
            for outcome, count in report["outcomes"].items():
                print(f"{outcome}: {count}")
            if report["top_failed_sources"]:
                print("Top sources of unsuccessful attempts:")
                for row in report["top_failed_sources"]:
                    print(f"  {row['source_ip']}: {row['attempts']}")
        return 0
    if args.logfile is None:
        raise SystemExit("A logfile is required unless --summary is set")
    if args.export is not None and args.export.exists():
        raise SystemExit(f"Export file already exists: {args.export}")

    try:
        # Rotated or damaged logs can contain stray bytes; replace them rather than abort.
        with args.logfile.open(encoding="utf-8", errors="replace") as handle:
            events = list(parse_lines(handle, args.year))
    except OSError as exc:
        raise SystemExit(f"Cannot read log file {args.logfile}: {exc.strerror or exc}") from exc
    connection = connect(args.database)
    inserted = save_events(connection, events)
    findings = detect_brute_force(connection, args.threshold)
    if args.window_seconds is not None:
        findings += detect_brute_force_window(connection, args.threshold, args.window_seconds)
    findings += detect_success_after_failures(connection, args.threshold)

    if args.anonymize:
        anonymizer = IpAnonymizer()
        findings = [anonymizer.finding(f) for f in findings]
    if args.export is not None:
        write_findings(args.export, findings, args.export_format)
    if args.as_json:
        print(json.dumps({"inserted": inserted, "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        print(f"Imported {inserted} new events into {args.database}")
        if not findings:
            print("No findings at the selected threshold.")
        for finding in findings:
            print(
                f"[{finding.severity.upper()}] {finding.rule} "
                f"{finding.source_ip}: {finding.summary}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
