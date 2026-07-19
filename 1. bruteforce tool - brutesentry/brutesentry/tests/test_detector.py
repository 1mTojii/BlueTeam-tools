import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from brutesentry.detector import BruteForceDetector


def test_flags_ip_after_threshold():
    d = BruteForceDetector(threshold=3, window_seconds=60)
    assert d.feed_event("1.2.3.4", "admin", timestamp=0, success=False) is None
    assert d.feed_event("1.2.3.4", "admin", timestamp=1, success=False) is None
    alert = d.feed_event("1.2.3.4", "admin", timestamp=2, success=False)
    assert alert is not None
    assert alert.ip == "1.2.3.4"
    assert alert.failure_count == 3


def test_does_not_flag_below_threshold():
    d = BruteForceDetector(threshold=5, window_seconds=60)
    for i in range(4):
        result = d.feed_event("1.2.3.4", "admin", timestamp=i, success=False)
        assert result is None


def test_success_resets_streak():
    d = BruteForceDetector(threshold=3, window_seconds=60)
    d.feed_event("1.2.3.4", "admin", timestamp=0, success=False)
    d.feed_event("1.2.3.4", "admin", timestamp=1, success=False)
    d.feed_event("1.2.3.4", "admin", timestamp=2, success=True)  # resets
    result = d.feed_event("1.2.3.4", "admin", timestamp=3, success=False)
    assert result is None  # only 1 failure since reset


def test_window_expiry_prevents_stale_flagging():
    d = BruteForceDetector(threshold=3, window_seconds=5)
    d.feed_event("1.2.3.4", "admin", timestamp=0, success=False)
    d.feed_event("1.2.3.4", "admin", timestamp=1, success=False)
    # This third failure is outside the window relative to timestamp=0,
    # so only 2 failures should be "in view" at this point.
    result = d.feed_event("1.2.3.4", "admin", timestamp=10, success=False)
    assert result is None


def test_does_not_alert_twice_for_same_streak():
    d = BruteForceDetector(threshold=2, window_seconds=60)
    d.feed_event("1.2.3.4", "admin", timestamp=0, success=False)
    first = d.feed_event("1.2.3.4", "admin", timestamp=1, success=False)
    second = d.feed_event("1.2.3.4", "admin", timestamp=2, success=False)
    assert first is not None
    assert second is None  # already flagged, don't spam


if __name__ == "__main__":
    test_flags_ip_after_threshold()
    test_does_not_flag_below_threshold()
    test_success_resets_streak()
    test_window_expiry_prevents_stale_flagging()
    test_does_not_alert_twice_for_same_streak()
    print("All tests passed.")
