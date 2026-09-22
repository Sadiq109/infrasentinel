import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .detectors import detect_brute_force
from .parser import parse_lines
from .storage import connect, save_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="infrasentinel",
        description="Parse Linux authentication logs and surface suspicious activity.",
    )
    parser.add_argument("logfile", type=Path, help="Path to a syslog/auth.log file")
    parser.add_argument("--database", type=Path, default=Path("infrasentinel.db"))
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.threshold < 1:
        raise SystemExit("--threshold must be at least 1")

    with args.logfile.open(encoding="utf-8") as handle:
        events = list(parse_lines(handle))
    connection = connect(args.database)
    inserted = save_events(connection, events)
    findings = detect_brute_force(connection, args.threshold)

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
