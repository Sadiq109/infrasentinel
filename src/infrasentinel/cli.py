import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .anonymize import IpAnonymizer
from .detectors import detect_brute_force, detect_success_after_failures
from .export import write_findings
from .parser import parse_lines
from .storage import connect, save_events
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
    parser.add_argument("--year", type=int, help="Year of the log (syslog timestamps have none); stores ISO timestamps")
    parser.add_argument("--anonymize", action="store_true", help="Replace source IPs with ip-001 style labels in output and exports")
    parser.add_argument("--export-format", choices=("csv", "jsonl"), default="csv")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.year is not None and not 1970 <= args.year <= 9999:
        raise SystemExit("--year must be between 1970 and 9999")
    if args.threshold < 1:
        raise SystemExit("--threshold must be at least 1")
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

    with args.logfile.open(encoding="utf-8") as handle:
        events = list(parse_lines(handle, args.year))
    connection = connect(args.database)
    inserted = save_events(connection, events)
    findings = detect_brute_force(connection, args.threshold)
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
