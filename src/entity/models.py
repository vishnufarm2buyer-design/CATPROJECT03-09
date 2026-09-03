"""
src/entity/models.py
--------------------
Dataclasses for the three entity tables: Identity, Asset, Session.

These are the "join keys" that allow the correlation engine to link events
across different source tools. For example:
  - An identity event says "alice@corp.com failed to log in"
  - An endpoint event says "WKSTN-042 ran powershell.exe"
  - A Session record says "alice@corp.com was logged into WKSTN-042 at 08:04"
  ⟹ The engine can now link these two events into a chain.

WHY DATACLASSES?
  Using dataclasses (instead of plain dicts) means:
  1. The schema is explicitly documented in code — you can't accidentally omit a field.
  2. Type hints give IDE auto-complete and catch bugs early.
  3. Easy to convert to dict for JSON serialization: dataclasses.asdict(obj).
"""

from __future__ import annotations

import dataclasses
from datetime import datetime


@dataclasses.dataclass
class Identity:
    """
    Represents a user account that may appear across multiple security tools.

    identity_id is the primary key — it must match the identity_id field in
    CommonEvent. In practice this is the user's UPN (User Principal Name),
    e.g. "alice@corp.com".
    """

    identity_id: str          # PK — e.g. "alice@corp.com"
    display_name: str         # Human-readable — "Alice Smith"
    email: str                # Used to cross-reference email tool events
    department: str | None    # OPTIONAL — not all identity providers export org data
    is_privileged: bool       # True if this account has admin/elevated privileges
                              # Privileged accounts are higher-risk and scored differently


@dataclasses.dataclass
class Asset:
    """
    Represents a physical or virtual device (workstation, server, VM).

    asset_id is the primary key — it must match the asset_id field in CommonEvent.
    In Phase 1 we use hostname as asset_id (simplest stable identifier).
    Phase 2 will add MAC address / hardware ID for more reliable identification
    in DHCP environments where IP addresses change.
    """

    asset_id: str             # PK — hostname used as stable identifier, e.g. "WKSTN-042"
    hostname: str             # Same as asset_id in Phase 1
    ip_address: str | None    # OPTIONAL — may change (DHCP); stored for display only
    os_type: str | None       # OPTIONAL — "windows" | "linux" | "macos"
    is_server: bool           # True if this is a server (higher blast radius if compromised)


@dataclasses.dataclass
class Session:
    """
    The critical join record that links an Identity to an Asset during a time window.

    This is what allows the engine to say:
      "alice@corp.com was logged into WKSTN-042 from 08:04 to 09:30,
       so any endpoint events on WKSTN-042 in that window belong to Alice's chain."

    logout_time is OPTIONAL because many endpoint tools do not emit logoff events.
    When logout_time is None, the session is treated as "still active" or
    "unknown end time" — the engine uses a configurable max_session_hours cap instead.
    """

    session_id: str           # Unique session identifier (from identity tool or generated)
    identity_id: str          # FK → Identity.identity_id
    asset_id: str             # FK → Asset.asset_id
    login_time: datetime      # When the session started (UTC)
    logout_time: datetime | None  # OPTIONAL — None means not yet logged off (or unknown)
