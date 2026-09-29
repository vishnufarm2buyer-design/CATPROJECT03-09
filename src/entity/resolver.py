"""
src/entity/resolver.py
----------------------
Builds and queries the entity map: identity_id <-> asset_id relationships.

WHAT ENTITY RESOLUTION DOES:
  After normalization, we have events like:
    - CommonEvent(source="identity", identity_id="alice@corp.com", asset_id="WKSTN-042")
    - CommonEvent(source="endpoint", identity_id="alice@corp.com", asset_id="WKSTN-042")

  The EntityResolver scans all events and builds a map:
    {
      "alice@corp.com": {"WKSTN-042"},  <- alice was seen on this machine
      "bob@corp.com":   {"WKSTN-017"},
    }

  This map is then used by the correlation rule engine to ask:
    "Given that alice@corp.com had suspicious login events, which assets
     should I check for suspicious endpoint events?"
    -> answer: WKSTN-042

PHASE 2 IMPROVEMENT — SESSION-TIME-BOUNDED RESOLUTION:
  Phase 1 used whole-mapping: once an identity touches an asset, ALL future
  events on that asset are attributed to that identity. This caused false
  positives on shared workstations (Risk R2).

  Phase 2 adds assets_for_identity_at(identity_id, at_time):
    - Only returns assets where the identity had an ACTIVE session at at_time
    - A session is active if login_time <= at_time <= logout_time
    - When logout_time is unknown, a configurable max_session_hours cap applies
    - This prevents attributing User B's activity to User A on a shared machine

SESSION OBJECTS:
  Identity events that include both identity_id and asset_id AND have event_type
  LOGIN_SUCCESS are used to create Session records. These provide precise linking.
  A LOGOUT event (if present) sets the session's logout_time.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from src.entity.models import Asset, Identity, Session
from src.normalize.schema import CommonEvent

logger = logging.getLogger(__name__)


class EntityResolver:
    """
    Builds identity<->asset mappings from normalized events.
    Supports both static (Phase 1) and session-bounded (Phase 2) lookups.

    Usage:
        resolver = EntityResolver()
        resolver.ingest(all_events)

        # Static (backward compat):
        assets = resolver.assets_for_identity("alice@corp.com")

        # Session-bounded (Phase 2 — fixes Risk R2):
        assets = resolver.assets_for_identity_at("alice@corp.com", suspicious_time)
    """

    def __init__(self) -> None:
        # identity_id -> set of asset_ids seen for that identity
        self._identity_to_assets: dict[str, set[str]] = defaultdict(set)
        # asset_id -> set of identity_ids seen on that asset
        self._asset_to_identities: dict[str, set[str]] = defaultdict(set)
        # Sessions: identity_id -> list of Session objects
        self._sessions: dict[str, list[Session]] = defaultdict(list)
        # Known Identity records (built from events)
        self._identities: dict[str, Identity] = {}
        # Known Asset records (built from events)
        self._assets: dict[str, Asset] = {}

    def ingest(self, events: list[CommonEvent]) -> None:
        """
        Scan all normalized events to build the entity map.

        For every event that has BOTH identity_id and asset_id, record the
        association. For identity login events with a session_id, also create
        a Session record.

        Args:
            events: All normalized CommonEvent objects from all sources.
        """
        session_count = 0
        link_count = 0

        for event in events:
            # ── Register Identity if seen for the first time ──────────────────
            if event.identity_id and event.identity_id not in self._identities:
                self._identities[event.identity_id] = Identity(
                    identity_id=event.identity_id,
                    display_name=event.identity_id,  # No HR lookup in Phase 1
                    email=event.identity_id,
                    department=None,
                    is_privileged=self._is_privileged_guess(event.identity_id),
                )

            # ── Register Asset if seen for the first time ─────────────────────
            if event.asset_id and event.asset_id not in self._assets:
                self._assets[event.asset_id] = Asset(
                    asset_id=event.asset_id,
                    hostname=event.asset_id,
                    ip_address=event.raw_payload.get("sourceIp")
                              or event.raw_payload.get("destinationIp"),
                    os_type=None,   # Not available in Phase 1 raw events
                    is_server="SRV" in event.asset_id.upper(),
                )

            # ── Link identity <-> asset ─────────────────────────────────────────
            if event.identity_id and event.asset_id:
                self._identity_to_assets[event.identity_id].add(event.asset_id)
                self._asset_to_identities[event.asset_id].add(event.identity_id)
                link_count += 1

                # ── Create Session from identity login events ─────────────────
                if (
                    event.source == "identity"
                    and event.event_type == "LOGIN_SUCCESS"
                ):
                    session_id = event.session_id or f"auto-{uuid.uuid4().hex[:8]}"
                    session = Session(
                        session_id=session_id,
                        identity_id=event.identity_id,
                        asset_id=event.asset_id,
                        login_time=event.timestamp,
                        logout_time=None,  # Not known at login time
                    )
                    self._sessions[event.identity_id].append(session)
                    session_count += 1

        logger.info(
            "[EntityResolver] Built map: %d identities, %d assets, %d links, %d sessions",
            len(self._identities),
            len(self._assets),
            link_count,
            session_count,
        )

    def assets_for_identity(self, identity_id: str) -> set[str]:
        """Return the set of asset_ids seen for this identity. Empty set if unknown."""
        return self._identity_to_assets.get(identity_id, set())

    def assets_for_identity_at(
        self,
        identity_id: str,
        at_time: datetime,
        max_session_hours: float = 8.0,
    ) -> set[str]:
        """
        Return assets where this identity had an ACTIVE session at at_time.

        A session is active if:
          - login_time <= at_time <= logout_time  (when logout_time is known)
          - login_time <= at_time <= login_time + max_session_hours  (when unknown)

        This fixes Risk R2: on a shared workstation, only the user who was
        logged in at the relevant time is linked to events on that asset.

        Args:
            identity_id:      The identity to look up.
            at_time:          The point in time to check.
            max_session_hours: Maximum assumed session duration when logout is unknown.

        Returns:
            Set of asset_ids with active sessions at at_time. Empty set if none.
        """
        sessions = self._sessions.get(identity_id, [])
        if not sessions:
            return set()

        max_duration = timedelta(hours=max_session_hours)
        active_assets: set[str] = set()

        for session in sessions:
            # Determine session end time
            if session.logout_time is not None:
                session_end = session.logout_time
            else:
                session_end = session.login_time + max_duration

            # Check if at_time falls within the session window
            if session.login_time <= at_time <= session_end:
                active_assets.add(session.asset_id)

        return active_assets

    def identities_for_asset(self, asset_id: str) -> set[str]:
        """Return the set of identity_ids seen on this asset. Empty set if unknown."""
        return self._asset_to_identities.get(asset_id, set())

    def sessions_for_identity(self, identity_id: str) -> list[Session]:
        """Return Session records for this identity, sorted by login_time."""
        return sorted(
            self._sessions.get(identity_id, []),
            key=lambda s: s.login_time,
        )

    def get_identity(self, identity_id: str) -> Identity | None:
        return self._identities.get(identity_id)

    def get_asset(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    @staticmethod
    def _is_privileged_guess(identity_id: str) -> bool:
        """
        Heuristic: guess if an account is privileged based on naming patterns.
        Phase 3 will replace this with an LDAP/HR system lookup.
        """
        lowered = identity_id.lower()
        privileged_hints = {"admin", "svc", "service", "root", "system", "dc", "domain"}
        return any(hint in lowered for hint in privileged_hints)
