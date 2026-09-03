# Data Schema

## Design Principles

1. **One common schema for all sources.** Every event, regardless of origin tool, becomes a `CommonEvent` after normalization. The correlation engine never sees raw tool-specific formats.
2. **Optional fields are explicit, not absent.** Fields that a source may not have (e.g., `asset_id` for a cloud login event) are present but set to `null`. This prevents KeyError bugs and makes missing data visible.
3. **`raw_payload` is always preserved.** The original event is stored verbatim. If a normalization bug strips a field, the raw data can be re-processed without re-ingesting from the source tool.
4. **`identity_id` and `asset_id` are the correlation keys.** These are the foreign keys that allow the entity resolution layer to link events across tools.

---

## 1. CommonEvent — The Normalized Event Schema

This is the central data structure. Every event entering the correlation engine is expressed in this format.

```python
@dataclass
class CommonEvent:
    # --- Required fields (all sources must provide these) ---
    event_id:    str          # Unique ID (UUID), generated at normalization time
    timestamp:   datetime     # UTC datetime of the event; parsed from source format
    source:      str          # Which tool produced this: "identity" | "endpoint" |
                              #   "email" | "network" | "cloud"
    event_type:  str          # Normalized event category (see Event Types table below)
    severity:    str          # "low" | "medium" | "high" | "critical"
    raw_payload: dict         # The original unmodified event dict from the source

    # --- Optional fields (set to None if source does not provide) ---
    identity_id: str | None   # User identifier (UPN, employee ID). None for events
                              #   that have no associated user (e.g., raw network flows)
    asset_id:    str | None   # Asset identifier (hostname, MAC). None for events that
                              #   have no associated device (e.g., cloud API calls with
                              #   no source host)
    session_id:  str | None   # Session identifier, if available. Links identity+asset
                              #   events that occurred within the same authenticated session
```

### Normalized Event Types (event_type field)

| event_type | Description | Typical Source |
|-----------|-------------|----------------|
| `LOGIN_SUCCESS` | Successful authentication | identity |
| `LOGIN_FAILED` | Failed authentication attempt | identity |
| `MFA_BYPASS` | MFA requirement skipped or bypassed | identity |
| `PASSWORD_RESET` | User password changed | identity |
| `PROCESS_EXEC` | Process execution on endpoint | endpoint |
| `FILE_WRITE` | File created or modified | endpoint |
| `NETWORK_CONN` | Outbound network connection from endpoint | endpoint |
| `EMAIL_CLICK` | User clicked a link in an email | email |
| `EMAIL_ATTACHMENT` | User opened an email attachment | email |
| `DNS_QUERY` | DNS query (potential C2 beacon) | network |
| `NET_FLOW` | Network flow between hosts | network |
| `CLOUD_API_CALL` | Cloud API invoked (e.g., S3 GetObject) | cloud |
| `CLOUD_ROLE_ASSUME` | Cloud role or privilege escalation | cloud |

---

## 2. Entity Tables — The Join Keys

These three tables are the "address book" that lets the engine link events across tools.

### Identity Table

```python
@dataclass
class Identity:
    identity_id:  str        # Primary key. Same value used in CommonEvent.identity_id
    display_name: str        # Human-readable name ("Alice Smith")
    email:        str        # Email address (used to cross-reference email events)
    department:   str | None # Optional organizational unit
    is_privileged: bool      # True if this account has admin/elevated privileges
```

### Asset Table

```python
@dataclass
class Asset:
    asset_id:    str         # Primary key. Same value used in CommonEvent.asset_id
    hostname:    str         # Machine hostname ("WKSTN-042")
    ip_address:  str | None  # IP at time of last known event (may change — DHCP)
    os_type:     str | None  # "windows" | "linux" | "macos"
    is_server:   bool        # True if this is a server (vs workstation)
```

### Session Table

```python
@dataclass
class Session:
    session_id:   str        # Unique session identifier
    identity_id:  str        # FK → Identity.identity_id
    asset_id:     str        # FK → Asset.asset_id
    login_time:   datetime   # When the session started (UTC)
    logout_time:  datetime | None  # When the session ended. None = still active
                                   # OPTIONAL — endpoint logs may not have logoff events
```

**The Session table is the critical join key.** To link an identity event to an endpoint event:
1. Find the `Session` record where `identity_id` matches AND the event timestamp falls between `login_time` and `logout_time`
2. Extract the `asset_id` from that session
3. Now endpoint events on that `asset_id` are linkable to this identity's events

---

## 3. Source Field Mapping Tables

These show how each source tool's raw field names map to CommonEvent fields.

### Identity Source → CommonEvent

| Raw Field (identity tool) | CommonEvent Field | Notes |
|--------------------------|------------------|-------|
| `userId` | `identity_id` | Direct mapping |
| `timestamp` | `timestamp` | Parsed to UTC datetime |
| `eventType` | `event_type` | Mapped via lookup table |
| `riskLevel` | `severity` | `"low"/"medium"/"high"` |
| `deviceId` | `asset_id` | **OPTIONAL** — present only for device-bound logins |
| `sessionId` | `session_id` | **OPTIONAL** |
| *(entire raw dict)* | `raw_payload` | Stored verbatim |

### Endpoint Source → CommonEvent

| Raw Field (endpoint tool) | CommonEvent Field | Notes |
|--------------------------|------------------|-------|
| `hostName` | `asset_id` | Used as asset identifier |
| `timestamp` | `timestamp` | Parsed to UTC datetime |
| `eventCategory` | `event_type` | Mapped via lookup table |
| `alertSeverity` | `severity` | Mapped to normalized scale |
| `loggedOnUser` | `identity_id` | **OPTIONAL** — may be null for system processes |
| *(entire raw dict)* | `raw_payload` | Stored verbatim |

---

## 4. CorrelationChain — The Output Schema

```python
@dataclass
class CorrelationChain:
    chain_id:        str           # UUID for this chain instance
    rule_name:       str           # Which rule fired ("BRUTE_FORCE_ENDPOINT", etc.)
    confidence:      float         # 0.0–1.0. Based on number of corroborating signals
    events:          list[CommonEvent]  # The events that make up this chain (ordered by time)
    identity_ids:    list[str]     # All identities involved
    asset_ids:       list[str]     # All assets involved
    detected_at:     datetime      # When the engine detected this chain (UTC)
    time_span_mins:  float         # Duration from first to last event in the chain
```

---

## 5. Optional Fields Summary

| Field | CommonEvent | Session | Why Optional |
|-------|------------|---------|-------------|
| `identity_id` | ✓ Optional | — | Network flow events have no user |
| `asset_id` | ✓ Optional | — | Cloud API call may have no source device |
| `session_id` | ✓ Optional | — | Most tools don't export session IDs |
| `logout_time` | — | ✓ Optional | Endpoint tools often miss logoff events |
| `ip_address` | — | ✓ Optional (Asset) | DHCP environments have changing IPs |
| `department` | — | — (Identity) | Not all identity providers export org data |
