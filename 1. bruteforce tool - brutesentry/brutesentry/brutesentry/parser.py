"""
Parses log lines into (timestamp, ip, username, success) tuples.

Supports:
  1. A simple built-in JSON-lines format (what the demo generator produces):
     {"ts": 1737200000.123, "ip": "10.0.0.5", "user": "admin", "success": false}

  2. A generic sshd-style auth.log line, e.g.:
     Jul 18 14:02:11 host sshd[1234]: Failed password for admin from 10.0.0.5 port 51322 ssh2
     Jul 18 14:02:15 host sshd[1234]: Accepted password for admin from 10.0.0.5 port 51322 ssh2
"""

from __future__ import annotations

import json
import re
from datetime import datetime

_SSHD_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"(?P<result>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?"
    r"(?P<user>\S+)\s+from\s+(?P<ip>[\d\.]+)"
)

_YEAR = datetime.now().year


def parse_line(line: str) -> tuple[float, str, str, bool] | None:
    line = line.strip()
    if not line:
        return None

    # Try JSON-lines format first
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            return float(obj["ts"]), str(obj["ip"]), str(obj.get("user", "?")), bool(obj.get("success", False))
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    # Fall back to sshd-style syslog format
    match = _SSHD_RE.search(line)
    if match:
        ts_str = f"{_YEAR} {match['month']} {match['day']} {match['time']}"
        try:
            ts = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S").timestamp()
        except ValueError:
            ts = 0.0
        success = match["result"] == "Accepted"
        return ts, match["ip"], match["user"], success

    return None
