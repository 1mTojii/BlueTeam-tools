"""Export flagged alerts to JSON/CSV, and optionally fire a webhook."""

from __future__ import annotations

import csv
import json
import urllib.request
from pathlib import Path

from .detector import Alert


def export_json(alerts: list[Alert], path: str) -> None:
    data = [a.to_dict() for a in alerts]
    Path(path).write_text(json.dumps(data, indent=2))


def export_csv(alerts: list[Alert], path: str) -> None:
    fieldnames = [
        "ip",
        "username",
        "failure_count",
        "window_seconds",
        "attempts_per_second",
        "first_seen",
        "last_seen",
        "severity",
    ]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(alert.to_dict())


def send_webhook(alert: Alert, webhook_url: str) -> bool:
    """
    Fires a simple Slack or Discord compatible webhook payload (both accept a
    high level "content"/"text" style JSON body with a message string).
    Returns True on a 2xx response, False otherwise. Never raises.
    """
    message = (
        f":rotating_light: **BruteSentry Alert** [{alert.severity}]\n"
        f"IP `{alert.ip}` triggered {alert.failure_count} failed logins "
        f"({alert.attempts_per_second} attempts/sec), last user tried: `{alert.username}`"
    )
    payload = json.dumps({"content": message, "text": message}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False
