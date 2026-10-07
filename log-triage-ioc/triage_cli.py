"""
Command line triage runner.

Usage:
    python triage_cli.py sample_data/auth.log sample_data/access.log --ioc sample_data/iocs.txt

Reads one or more log files, runs detections, prints a findings summary and
writes a full JSON incident report to report.json.
"""

import argparse
import json

from src.triage import parse_logs, Detector, build_timeline, build_report


def main():
    ap = argparse.ArgumentParser(description="Log triage and IOC scanner")
    ap.add_argument("logs", nargs="+", help="log files to analyse")
    ap.add_argument("--ioc", help="file with one IOC IP per line")
    ap.add_argument("--out", default="report.json", help="report output path")
    args = ap.parse_args()

    lines = []
    for path in args.logs:
        with open(path, encoding="utf-8") as f:
            lines.extend(f.readlines())

    ioc_ips = []
    if args.ioc:
        with open(args.ioc, encoding="utf-8") as f:
            ioc_ips = [ln.strip() for ln in f if ln.strip()]

    events = parse_logs(lines)
    findings = Detector(ioc_ips=ioc_ips).run(events)
    report = build_report(events, findings)
    report["timeline"] = build_timeline(events)

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Analysed {len(events)} events from {len(args.logs)} file(s).")
    print(f"{len(findings)} finding(s):\n")
    for fnd in findings:
        print(f"  [{fnd.severity.upper():6}] {fnd.category:22} {fnd.source_ip:16} "
              f"x{fnd.count}")
        print(f"           {fnd.description}")
        print(f"           {fnd.first_seen}  to  {fnd.last_seen}\n")
    print(f"Full report with timeline written to {args.out}")


if __name__ == "__main__":
    main()
