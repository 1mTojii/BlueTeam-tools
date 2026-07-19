"""Colored terminal reporting for BruteSentry alerts."""

from __future__ import annotations

from datetime import datetime

from .detector import Alert

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

COLORS = {
    "LOW": "\033[36m",       # cyan
    "MEDIUM": "\033[33m",    # yellow
    "HIGH": "\033[38;5;208m",  # orange
    "CRITICAL": "\033[31m",  # red
}

BANNER = r"""
 ____                 _        ____             _
| __ ) _ __ _   _ ___| |_ ___ / ___|  ___ _ __ | |_ _ __ _   _
|  _ \| '__| | | / _ \ __/ _ \\___ \ / _ \ '_ \| __| '__| | | |
| |_) | |  | |_| |  __/ ||  __/___) |  __/ | | | |_| |  | |_| |
|____/|_|   \__,_|\___|\__\___|____/ \___|_| |_|\__|_|   \__, |
                                                          |___/
        BruteSentry -- guarding your blindsidez
"""


def print_banner() -> None:
    print(f"{BOLD}{BANNER}{RESET}")


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def print_alert(alert: Alert) -> None:
    color = COLORS.get(alert.severity, "")
    print(
        f"{color}{BOLD}[{alert.severity}]{RESET} "
        f"{BOLD}{alert.ip}{RESET} flagged -- "
        f"{alert.failure_count} failed logins in "
        f"{_fmt_time(alert.first_seen)}\u2192{_fmt_time(alert.last_seen)} "
        f"({alert.attempts_per_second} attempts/sec, last user tried: '{alert.username}')"
    )


def print_summary(alerts: list[Alert], events_processed: int) -> None:
    print(f"\n{DIM}{'-' * 60}{RESET}")
    print(f"{BOLD}Summary{RESET}")
    print(f"  events processed : {events_processed}")
    print(f"  ips flagged      : {len(alerts)}")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sum(1 for a in alerts if a.severity == level)
        if count:
            color = COLORS[level]
            print(f"  {color}{level:<9}{RESET}: {count}")
    print(f"{DIM}{'-' * 60}{RESET}")
