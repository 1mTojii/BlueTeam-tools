"""
Core detection engine for BruteSentry.

The logic is intentionally simple: track failed login timestamps per source IP
in a sliding time window. Once an IP crosses a configurable failure threshold
inside that window, it gets flagged as a brute force attempt with a severity
score based on how far past the threshold it went and how fast the attempts
came in.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field


@dataclass
class Alert:
    ip: str
    username: str
    failure_count: int
    window_seconds: float
    first_seen: float
    last_seen: float
    severity: str

    @property
    def attempts_per_second(self) -> float:
        span = max(self.last_seen - self.first_seen, 0.001)
        return round(self.failure_count / span, 2)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "username": self.username,
            "failure_count": self.failure_count,
            "window_seconds": self.window_seconds,
            "attempts_per_second": self.attempts_per_second,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "severity": self.severity,
        }


def _severity(failure_count: int, threshold: int, attempts_per_second: float) -> str:
    """Very simple scoring: how far over threshold + how fast the attempts came in."""
    overshoot_ratio = failure_count / threshold

    if overshoot_ratio >= 3 or attempts_per_second >= 5:
        return "CRITICAL"
    if overshoot_ratio >= 2 or attempts_per_second >= 2:
        return "HIGH"
    if overshoot_ratio >= 1.5:
        return "MEDIUM"
    return "LOW OR CLOSE TO NON"


class BruteForceDetector:
    """
    Sliding window failed login tracker.

    feed_event is called upon per login attempt.

    When an IPs failed attempts inside "window_seconds" crosses
    the "threshold", an Alert is emitted (it is emitted once per IP until it "cools down" by
    falling back under threshold and is retriggered later).
    """

    def __init__(self, threshold: int = 5, window_seconds: float = 60.0):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)
        self._already_flagged: set[str] = set()
        self.alerts: list[Alert] = []

    def _prune(self, ip: str, now: float) -> None:
        dq = self._events[ip]
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def feed_event(
        self,
        ip: str,
        username: str,
        timestamp: float | None = None,
        success: bool = False,
    ) -> Alert | None:
        now = timestamp if timestamp is not None else time.time()

        if success:
            # A successful login clears the slate for that IP -- resets suspicion.
            self._events[ip].clear()
            self._already_flagged.discard(ip)
            return None

        self._events[ip].append((now, username))
        self._prune(ip, now)

        dq = self._events[ip]
        count = len(dq)

        if count < self.threshold:
            self._already_flagged.discard(ip)
            return None

        if ip in self._already_flagged:
            return None  # already alerted for this streak, don't spam

        first_seen = dq[0][0]
        last_seen = dq[-1][0]
        span = max(last_seen - first_seen, 0.001)
        rate = round(count / span, 2)
        severity = _severity(count, self.threshold, rate)

        alert = Alert(
            ip=ip,
            username=username,
            failure_count=count,
            window_seconds=self.window_seconds,
            first_seen=first_seen,
            last_seen=last_seen,
            severity=severity,
        )
        self.alerts.append(alert)
        self._already_flagged.add(ip)
        return alert
