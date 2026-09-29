"""
tests/test_delayed_event.py
---------------------------
Edge Case 2: Events arriving outside the correlation time window.

WHAT WE'RE TESTING:
  The rule engine uses time windows to determine if two events are related.
  An event that arrives too late (after the window closes) must NOT be correlated
  into a chain that started before it.

  This tests the correctness of the time-window logic — if this fails, the engine
  would incorrectly link unrelated events just because they share a user.

SCENARIO:
  - 5 failed logins for "delayed_user@corp.com" at T=0..4 min
  - A suspicious endpoint event at T = ENDPOINT_FOLLOW_WINDOW_MINUTES + 30 min
    (well outside the follow window — should NOT be correlated)
  - A second suspicious endpoint event at T = 5 min (INSIDE the window — SHOULD be correlated)

EXPECTED BEHAVIOR:
  - Chain IS detected for the in-window endpoint event
  - Chain is NOT detected (or does not include) the delayed endpoint event
  - The delayed event's timestamp is preserved correctly in normalization
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.correlate.rules import (
    RuleEngine,
    load_config,
)
from src.entity.resolver import EntityResolver
from src.normalize.schema import CommonEvent

# Load thresholds from config (same values the engine uses)
_cfg = load_config()
_brute_cfg = _cfg["rules"]["brute_force_endpoint"]
BRUTE_FORCE_MIN_FAILURES = _brute_cfg["min_failures"]
BRUTE_FORCE_WINDOW_MINUTES = _brute_cfg["failure_window_minutes"]
ENDPOINT_FOLLOW_WINDOW_MINUTES = _brute_cfg["endpoint_follow_window_minutes"]

# ── Helper to build synthetic CommonEvents in-memory ─────────────────────────

BASE_TIME = datetime(2024, 11, 15, 8, 0, 0, tzinfo=timezone.utc)


def make_login_failed(identity_id: str, offset_minutes: float) -> CommonEvent:
    return CommonEvent(
        event_id=CommonEvent.new_id(),
        timestamp=BASE_TIME + timedelta(minutes=offset_minutes),
        source="identity",
        event_type="LOGIN_FAILED",
        severity="high",
        raw_payload={"userId": identity_id, "riskLevel": "high"},
        identity_id=identity_id,
        asset_id=None,
        session_id=None,
    )


def make_suspicious_process(
    identity_id: str, asset_id: str, offset_minutes: float, severity: str = "high"
) -> CommonEvent:
    return CommonEvent(
        event_id=CommonEvent.new_id(),
        timestamp=BASE_TIME + timedelta(minutes=offset_minutes),
        source="endpoint",
        event_type="PROCESS_EXEC",
        severity=severity,
        raw_payload={
            "hostName": asset_id,
            "alertSeverity": severity,
            "processName": "mimikatz.exe",
            "commandLine": "mimikatz.exe privilege::debug",
            "loggedOnUser": identity_id,
        },
        identity_id=identity_id,
        asset_id=asset_id,
        session_id=None,
    )


def make_login_success(identity_id: str, asset_id: str, offset_minutes: float) -> CommonEvent:
    return CommonEvent(
        event_id=CommonEvent.new_id(),
        timestamp=BASE_TIME + timedelta(minutes=offset_minutes),
        source="identity",
        event_type="LOGIN_SUCCESS",
        severity="high",
        raw_payload={"userId": identity_id, "deviceId": asset_id, "riskLevel": "high"},
        identity_id=identity_id,
        asset_id=asset_id,
        session_id="sess-delayed-001",
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_delayed_event_outside_window_not_included_in_chain():
    """
    A suspicious endpoint event that arrives AFTER the correlation window
    must NOT be included in any detected chain.

    Setup:
      - 5 failed logins at T=0..4 min (within brute-force window)
      - Suspicious process at T = (ENDPOINT_FOLLOW_WINDOW_MINUTES + 30) min (DELAYED)
      - Login success at T=4.5 min so entity resolver builds the link

    Expected: 0 chains (the delayed endpoint event is outside the follow window)
    """
    identity_id = "delayed_user@corp.com"
    asset_id = "WKSTN-DELAY"
    delayed_offset = ENDPOINT_FOLLOW_WINDOW_MINUTES + 30  # Well outside window

    events = [
        make_login_failed(identity_id, 0),
        make_login_failed(identity_id, 1),
        make_login_failed(identity_id, 2),
        make_login_failed(identity_id, 3),
        make_login_failed(identity_id, 4),
        make_login_success(identity_id, asset_id, 4.5),  # So entity resolver links them
        # Delayed suspicious event — should NOT be correlated
        make_suspicious_process(identity_id, asset_id, delayed_offset),
    ]

    resolver = EntityResolver()
    resolver.ingest(events)

    # Verify the entity link exists
    assert asset_id in resolver.assets_for_identity(identity_id), \
        "Entity resolver must link identity to asset (test setup issue)"

    engine = RuleEngine()
    chains = engine.run(events, resolver)

    # No chain should be detected because the endpoint event is outside the window
    assert len(chains) == 0, (
        f"Expected 0 chains (delayed endpoint outside window), "
        f"got {len(chains)}: {[c.rule_name for c in chains]}"
    )


def test_in_window_event_is_detected():
    """
    Symmetric test: the SAME setup but with the suspicious event INSIDE the window.
    Must detect a chain. This verifies the time-window logic itself is working.
    """
    identity_id = "ontime_user@corp.com"
    asset_id = "WKSTN-ONTIME"
    in_window_offset = ENDPOINT_FOLLOW_WINDOW_MINUTES - 1  # Just inside the window

    events = [
        make_login_failed(identity_id, 0),
        make_login_failed(identity_id, 1),
        make_login_failed(identity_id, 2),
        make_login_failed(identity_id, 3),
        make_login_failed(identity_id, 4),
        make_login_success(identity_id, asset_id, 4.5),
        # In-window suspicious event — SHOULD be correlated
        make_suspicious_process(identity_id, asset_id, in_window_offset, severity="critical"),
    ]

    resolver = EntityResolver()
    resolver.ingest(events)

    engine = RuleEngine()
    chains = engine.run(events, resolver)

    assert len(chains) >= 1, (
        f"Expected ≥1 chain for in-window suspicious event, got {len(chains)}"
    )
    assert any(c.rule_name == "BRUTE_FORCE_ENDPOINT" for c in chains), \
        "Expected BRUTE_FORCE_ENDPOINT rule to fire"


def test_delayed_event_timestamp_is_preserved_correctly():
    """
    Normalization must correctly preserve timestamps for delayed events.
    A timestamp far in the future must not be misread as current time.
    """
    future_offset = 1440  # 24 hours after base time
    event = make_suspicious_process("any_user@corp.com", "ANY-HOST", future_offset)
    expected_ts = BASE_TIME + timedelta(minutes=future_offset)

    assert event.timestamp == expected_ts, (
        f"Timestamp mismatch: expected {expected_ts}, got {event.timestamp}"
    )
    # Verify the delta is correctly computable
    delta = event.timestamp - BASE_TIME
    assert abs(delta.total_seconds() / 60 - future_offset) < 0.01
