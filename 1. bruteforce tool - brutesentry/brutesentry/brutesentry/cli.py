"""
BruteSentry CLI.

Usage:
    python -m brutesentry.cli --log sample_logs/auth.log
    python -m brutesentry.cli --log sample_logs/auth.log --threshold 4 --window 30
    python -m brutesentry.cli --follow --log /var/log/auth.log       # tail -f style
    python -m brutesentry.cli --log sample_logs/auth.log --json out.json --csv out.csv
    python -m brutesentry.cli --log sample_logs/auth.log --webhook https://discord.com/api/webhooks/...
"""

from __future__ import annotations

import argparse
import sys
import time

from .detector import BruteForceDetector
from .exporter import export_csv, export_json, send_webhook
from .parser import parse_line
from .reporter import print_alert, print_banner, print_summary


def build_arg_prsr() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="brutesentry",
        description="Detect brute-force login attempts from an auth log.",
    )
    p.add_argument("--log", required=True, help="Path to log file (JSON-lines or sshd-style)")
    p.add_argument("--threshold", type=int, default=5, help="Failures before flagging an IP (default: 5)")
    p.add_argument("--window", type=float, default=60.0, help="Sliding window in seconds (default: 60)")
    p.add_argument("--follow", action="store_true", help="Tail the log file live, like `tail -f`")
    p.add_argument("--json", metavar="PATH", help="Export flagged alerts to a JSON file")
    p.add_argument("--csv", metavar="PATH", help="Export flagged alerts to a CSV file")
    p.add_argument("--webhook", metavar="URL", help="POST each new alert to this Slack/Discord-style webhook URL")
    p.add_argument("--quiet", action="store_true", help="Suppress the banner")
    return p


def _process_line(line: str, detector: BruteForceDetector, webhook: str | None) -> bool:
    parsed = parse_line(line)
    if parsed is None:
        return False
    ts, ip, user, success = parsed
    alert = detector.feed_event(ip, user, timestamp=ts, success=success)
    if alert:
        print_alert(alert)
        if webhook:
            send_webhook(alert, webhook)
    return True


def run(argv: list[str] | None = None) -> int:
    args = build_arg_prsr().parse_args(argv)
    detector = BruteForceDetector(threshold=args.threshold, window_seconds=args.window)

    if not args.quiet:
        print_banner()
        print(f"threshold={args.threshold} failures / window={args.window}s\n")

    events_processed = 0

    try:
        if args.follow:
            with open(args.log, "r") as f:
                f.seek(0, 2)  # jump to end of file, like tail -f
                print(f"Following {args.log} ... Ctrl+C to stop\n")
                try:
                    while True:
                        line = f.readline()
                        if not line:
                            time.sleep(0.5)
                            continue
                        if _process_line(line, detector, args.webhook):
                            events_processed += 1
                except KeyboardInterrupt:
                    print("\nStopped following.")
        else:
            with open(args.log, "r") as f:
                for line in f:
                    if _process_line(line, detector, args.webhook):
                        events_processed += 1
    except FileNotFoundError:
        print(f"Error: log file not found: {args.log}", file=sys.stderr)
        return 1

    print_summary(detector.alerts, events_processed)

    if args.json:
        export_json(detector.alerts, args.json)
        print(f"Wrote JSON export -> {args.json}")
    if args.csv:
        export_csv(detector.alerts, args.csv)
        print(f"Wrote CSV export -> {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(run())
