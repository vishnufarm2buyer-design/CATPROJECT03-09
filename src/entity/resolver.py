"""
src/entity/resolver.py
----------------------
Builds and queries the entity map: identity_id ↔ asset_id relationships.

WHAT ENTITY RESOLUTION DOES:
  After normalization, we have events like:
    - CommonEvent(source="identity", identity_id="alice@corp.com", asset_id="WKSTN-042")
    - CommonEvent(source="endpoint", identity_id="alice@corp.com", asset_id="WKSTN-042")

  The EntityResolver scans all events and builds a map:
    {
      "alice@corp.com": {"WKSTN-042"},  ← alice was seen on this machine
      "bob@corp.com":   {"WKSTN-017"},
    }

  This map is then used by the correlation rule engine to ask:
    "Given that alice@corp.com had suspicious login events, which assets
     should I check for suspicious endpoint events?"
    → answer: WKSTN-042

PHASE 1 LIMITATIONS:
  - Mapping is built from events themselves (no external HR/CMDB lookup).
  - One identity can map to multiple assets (shared workstations).
  - The engine will flag all assets linked to an identity when a chain starts.
  - Phase 2 will add Session-level time-bounded linking to avoid false positives
    from shared workstations (Risk R2 in the risk register).

SESSION OBJECTS:
  Identity events that include both identity_id and asset_id AND have a sessionId
  are used to create Session records. These provide the most precise linking.
  Events without sessionId fall back to a "seen together" heuristic.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from src.entity.models import Asset, Identity, Session
from src.normalize.schema import CommonEvent

logger = logging.getLogger(__name__)


class EntityResolver:
    """
    Builds identity↔asset mappings from normalized events.

    Usage:
        resolver = EntityResolver()
        resolver.ingest(all_events)
        assets = resolver.assets_for_identity("alice@corp.com")
        identities = resolver.identities_for_asset("WKSTN-042")
    """

    def __init__(self) -> None:
        # identity_id → set of asset_ids seen for that identity
        self._identity_to_assets: dict[str, set[str]] = defaultdict(set)
        # asset_id → set of identity_ids seen on that asset
        self._asset_to_identities: dict[str, set[str]] = defaultdict(set)
        # Sessions: identity_id → list of Session objects
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

            # ── Link identity ↔ asset ─────────────────────────────────────────
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
        Phase 2 will replace this with an LDAP/HR system lookup.
        """
        lowered = identity_id.lower()
        privileged_hints = {"admin", "svc", "service", "root", "system", "dc", "domain"}
        return any(hint in lowered for hint in privileged_hints)
