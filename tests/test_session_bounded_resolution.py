"""
tests/test_session_bounded_resolution.py
-----------------------------------------
Tests for Phase 2's session-time-bounded entity resolution (fixes Risk R2).

WHAT WE'RE TESTING:
  The old Phase 1 resolver used whole-mapping: once alice@corp.com logged
  into WKSTN-SHARED, alice was linked to that asset FOREVER. If bob@corp.com
  later logged in and ran suspicious processes, the engine would falsely
  attribute bob's activity to alice's chain.

  The new assets_for_identity_at(identity_id, at_time) method only returns
  assets where the identity had an ACTIVE session at that specific point in
  time. This prevents shared-workstation false positives.

TEST SCENARIOS:
  1. Shared workstation: User A session 08:00-09:00, User B session 10:00+.
     Suspicious event at 10:30 should NOT link to User A.
  2. Active session correctly includes events within bounds.
  3. Null logout_time with max_session_hours cap.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.entity.resolver import EntityResolver
from src.normalize.schema import CommonEvent


def _make_event(
    source: str,
    event_type: str,
    identity_id: str | None,
    asset_id: str | None,
    minutes_offset: float,
    severity: str = "low",
    session_id: str | None = None,
) -> CommonEvent:
    """Helper to create a CommonEvent at a specific time offset."""
    base = datetime(2024, 11, 15, 7, 0, 0, tzinfo=timezone.utc)
    return CommonEvent(
        event_id=CommonEvent.new_id(),
        timestamp=base + timedelta(minutes=minutes_offset),
        source=source,
        event_type=event_type,
        severity=severity,
        raw_payload={},
        identity_id=identity_id,
        asset_id=asset_id,
        session_id=session_id,
    )


class TestSharedWorkstationFalsePositive:
    """
    The core Risk R2 fix test:
    User A logs into SHARED-WS at 08:00, logs out at 09:00.
    User B logs into SHARED-WS at 10:00.
    Suspicious activity on SHARED-WS at 10:30 should NOT be attributed to User A.
    """

    def setup_method(self):
        """Create events for the shared workstation scenario."""
        self.events = [
            # User A login at 08:00 (T=60 min from base 07:00)
            _make_event("identity", "LOGIN_SUCCESS", "userA@corp.com",
                        "SHARED-WS", 60.0, session_id="sess-A-001"),
            # User A endpoint activity at 08:30 (T=90)
            _make_event("endpoint", "PROCESS_EXEC", "userA@corp.com",
                        "SHARED-WS", 90.0),
            # User B login at 10:00 (T=180)
            _make_event("identity", "LOGIN_SUCCESS", "userB@corp.com",
                        "SHARED-WS", 180.0, session_id="sess-B-001"),
            # Suspicious activity at 10:30 (T=210) — this is User B's session
            _make_event("endpoint", "PROCESS_EXEC", "userB@corp.com",
                        "SHARED-WS", 210.0, severity="critical"),
        ]
        self.resolver = EntityResolver()
        self.resolver.ingest(self.events)

    def test_static_mapping_links_both_users(self):
        """
        The old static mapping returns SHARED-WS for BOTH users
        (this is the Phase 1 behavior that caused false positives).
        """
        assert "SHARED-WS" in self.resolver.assets_for_identity("userA@corp.com")
        assert "SHARED-WS" in self.resolver.assets_for_identity("userB@corp.com")

    def test_session_bounded_excludes_user_a_at_10_30(self):
        """
        At 10:30 (T=210), User A's session (started at 08:00) should NOT
        be active anymore. assets_for_identity_at should return empty set.
        This is the KEY FIX for Risk R2.
        """
        at_time = datetime(2024, 11, 15, 7, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=210)
        # User A's session started at T=60 (08:00). With max_session_hours=2,
        # it expires at 10:00 (T=180). At 10:30 (T=210), User A is NOT active.
        assets_a = self.resolver.assets_for_identity_at(
            "userA@corp.com", at_time, max_session_hours=2.0
        )
        assert "SHARED-WS" not in assets_a, (
            "User A should NOT be linked to SHARED-WS at 10:30 "
            "(session expired). This was the Risk R2 false positive."
        )

    def test_session_bounded_includes_user_b_at_10_30(self):
        """
        At 10:30, User B's session (started at 10:00) IS active.
        """
        at_time = datetime(2024, 11, 15, 7, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=210)
        assets_b = self.resolver.assets_for_identity_at(
            "userB@corp.com", at_time, max_session_hours=2.0
        )
        assert "SHARED-WS" in assets_b, (
            "User B SHOULD be linked to SHARED-WS at 10:30 (active session)"
        )


class TestSessionBounds:
    """Test that session window boundaries work correctly."""

    def test_event_within_session_window(self):
        """Event 30 minutes into a session with max_session_hours=1 should match."""
        events = [
            _make_event("identity", "LOGIN_SUCCESS", "test@corp.com",
                        "WS-001", 0.0, session_id="sess-001"),
        ]
        resolver = EntityResolver()
        resolver.ingest(events)

        at_time = datetime(2024, 11, 15, 7, 30, 0, tzinfo=timezone.utc)
        assets = resolver.assets_for_identity_at("test@corp.com", at_time, max_session_hours=1.0)
        assert "WS-001" in assets

    def test_event_outside_max_session_cap(self):
        """Event 10 hours after login with max_session_hours=8 should NOT match."""
        events = [
            _make_event("identity", "LOGIN_SUCCESS", "test@corp.com",
                        "WS-001", 0.0, session_id="sess-001"),
        ]
        resolver = EntityResolver()
        resolver.ingest(events)

        at_time = datetime(2024, 11, 15, 17, 0, 0, tzinfo=timezone.utc)  # 10 hours later
        assets = resolver.assets_for_identity_at("test@corp.com", at_time, max_session_hours=8.0)
        assert "WS-001" not in assets

    def test_no_sessions_returns_empty(self):
        """Identity with no sessions returns empty set."""
        resolver = EntityResolver()
        resolver.ingest([])
        at_time = datetime(2024, 11, 15, 8, 0, 0, tzinfo=timezone.utc)
        assets = resolver.assets_for_identity_at("nobody@corp.com", at_time)
        assert assets == set()
