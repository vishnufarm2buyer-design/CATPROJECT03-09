# Phase 1 Write-Up: Attack-Chain Correlation Engine (35% Complete)

---

## 1. Stakeholder Assumptions

**Who uses this system:**

| Role | Use |
|------|-----|
| SOC Analyst (Tier 1/2) | Receives chain alerts instead of N separate tool alerts; triages and escalates |
| Incident Responder | Uses chain timeline to reconstruct multi-stage attack without manual pivoting |
| Security Lead | Defines correlation rules and time-window thresholds; reviews audit trail |

**Current workflow ("isolated-tool review"):** Each security tool fires its own alert. A brute-force attack on the identity tool and a suspicious PowerShell launch on the endpoint tool generate separate tickets. An analyst manually cross-references them — looking up which user was logged into the compromised machine, comparing timestamps, and pivoting between 3–5 separate dashboards. This takes 15–45 minutes and depends entirely on analyst skill. During high-alert periods the queue overwhelms Tier-1 and correlated events are missed.

**Constraints:**
- Must not replace existing SIEM or security tools. The engine reads from them via file export (Phase 1) or webhook (Phase 2). Read-only integration.
- Must degrade gracefully if a source is missing or delayed. If the endpoint file is absent, identity-only correlations continue. No crash.
- Every correlation decision must be explainable and logged to an audit trail.

**Success definition:** Time-to-correlate drops from 15–45 min (manual) to < 1 min (automated). Deterministic detection: any event stream matching a rule is always caught, regardless of analyst skill or queue depth.

---

## 2. Architecture

The engine is a five-layer pipeline:

```
[Identity Tool] [Endpoint Tool] [Email*] [Network*] [Cloud*]
       ↓               ↓
  [Identity Adapter] [Endpoint Adapter]        ← src/ingest/
       ↓               ↓
        [Normalization Layer]                  ← src/normalize/
           (CommonEvent schema)
                 ↓
        [Entity Resolution]                    ← src/entity/
           identity_id <-> asset_id
                 ↓
    [Baseline]     [Rule Engine]               ← src/correlate/
    (naive join)   (Rule 1 + Rule 2)
                 ↓
        [CorrelationChain output]
                 ↓
    [stdout alert]   [Audit Trail JSONL]       ← src/audit/
```
*Phase 2 sources

**Layer walkthrough:**

1. **Ingestion (src/ingest/):** Each source tool has its own adapter. Adapters read JSON exports, validate required fields, and return lists of raw dicts. If a source file doesn't exist, the adapter returns `[]` — graceful degradation is implemented at this layer, not upstream.

2. **Normalization (src/normalize/):** All raw events are mapped to `CommonEvent` — a single dataclass with fields: `event_id`, `timestamp` (UTC), `source`, `event_type`, `severity`, `raw_payload`, plus optional `identity_id`, `asset_id`, `session_id`. After this step, the rest of the pipeline never sees source-specific formats. Adding a Phase 2 source requires only one new adapter + one new field-mapping function.

3. **Entity Resolution (src/entity/):** Scans all normalized events to build a two-way map: `identity_id → set[asset_id]` and `asset_id → set[identity_id]`. Login events with both `identity_id` and `asset_id` create `Session` records. This is the join key that lets the engine link "alice failed to log in" to "WKSTN-042 ran powershell.exe."

4. **Correlation (src/correlate/):** Two sub-components. The **baseline** (naive join) groups events by identity and pairs any two within a 10-minute window — no chain logic, pure coincidence-of-time matching. This is the comparison point. The **rule engine** evaluates named rules, each of which specifies a causal sequence: rule `BRUTE_FORCE_ENDPOINT` requires N failed logins within T minutes AND a suspicious endpoint event on a linked asset within T' minutes after the last failure.

5. **Output (src/audit/):** Every decision — ingestion error, entity link, rule fire, chain created — is appended to `audit_trail.jsonl` as a single JSON line. Append-only. Never modified.

**Where it plugs into existing tools:** Read-only. Reads from the same JSON log files the tools already write. Does not modify any existing tool or database.

---

## 3. Data Schema

**CommonEvent** (the normalized event — all sources map into this):

| Field | Type | Optional | Purpose |
|-------|------|----------|---------|
| event_id | str (UUID) | No | Unique ID per event, generated at normalization |
| timestamp | datetime (UTC) | No | When the event occurred |
| source | str | No | "identity" or "endpoint" (5 values total) |
| event_type | str | No | Normalized category: LOGIN_FAILED, PROCESS_EXEC, etc. |
| severity | str | No | "low" / "medium" / "high" / "critical" |
| raw_payload | dict | No | Original event preserved verbatim for re-processing |
| identity_id | str | **Yes** | User identifier. None for system processes / raw flows |
| asset_id | str | **Yes** | Device identifier. None for cloud API calls without a host |
| session_id | str | **Yes** | Session link. None if tool doesn't export session IDs |

**Entity tables (the join keys):**
- `Identity`: `identity_id` (PK), display_name, email, department (optional), is_privileged
- `Asset`: `asset_id` (PK), hostname, ip_address (optional), os_type (optional), is_server
- `Session`: `session_id` (PK), `identity_id` (FK), `asset_id` (FK), login_time, `logout_time` (optional — many endpoint tools don't emit logoff events)

**Why optional fields matter:** `identity_id = None` is the signal for "this event has no user context" — e.g., a scheduled backup process. Without `Optional`, you'd either have to invent a fake identity or crash on missing data. The engine handles `None` gracefully throughout.

---

## 4. Baseline Description

**What it is:** The naive join baseline (`src/correlate/baseline.py`) simulates the "isolated-tool review" workflow in code. It groups events by `identity_id`, then finds all pairs of events for the same identity that fall within a 10-minute window of each other. It returns every such pair as a "correlation" — no chain logic, no causal reasoning.

**Why it's the baseline:** This is exactly what a Tier-1 analyst does manually: "I see alice@corp.com in two alerts, and the timestamps are close — must be related." The baseline automates that specific (flawed) logic.

**Phase 1 result on sample data:**
- 30 events (15 identity + 15 endpoint), 5 identities
- **Baseline produced 69 raw correlations**
- **Rule engine produced 2 chains**

The 69 vs 2 gap quantifies the false-positive cost of naive matching. 67 of those 69 "correlations" are pairs like "alice's routine login + her Chrome launch" — coincidental timing, not attack behavior. Phase 2 will measure this formally with precision/recall metrics.

---

## 5. Skeleton MVP: What It Currently Does

**End-to-end run (`python main.py`) does:**
1. Loads 15 identity events + 15 endpoint events from JSON files
2. Normalizes all 30 to CommonEvent (0 normalization errors)
3. Builds entity map: 5 identities, 6 assets, 4 sessions
4. Runs baseline: 69 raw correlations
5. Runs rule engine: detects **2 chains**

**Chain 1 — BRUTE_FORCE_ENDPOINT (95% confidence):**
```
08:01:00 [identity] LOGIN_FAILED   alice@corp.com
08:01:30 [identity] LOGIN_FAILED   alice@corp.com
08:02:00 [identity] LOGIN_FAILED   alice@corp.com
08:02:30 [identity] LOGIN_FAILED   alice@corp.com
08:03:10 [identity] LOGIN_FAILED   alice@corp.com
08:05:30 [endpoint] PROCESS_EXEC   alice@corp.com → WKSTN-042  (powershell -enc)
08:06:00 [endpoint] NETWORK_CONN   alice@corp.com → WKSTN-042  (→ 185.220.101.45:4444)
08:08:00 [endpoint] PROCESS_EXEC   alice@corp.com → WKSTN-042  (svchost32.exe -persist)
```
5 failed logins within 2 minutes → suspicious encoded PowerShell → C2 outbound connection → persistence dropper.

**Chain 2 — MFA_BYPASS_COMPROMISE (85% confidence):**
```
08:04:00 [identity] LOGIN_SUCCESS  alice@corp.com
08:04:45 [identity] MFA_BYPASS     alice@corp.com  (45 sec after login)
08:05:30 [endpoint] PROCESS_EXEC   alice@corp.com → WKSTN-042  (powershell)
08:06:00 [endpoint] NETWORK_CONN   alice@corp.com → WKSTN-042
08:08:00 [endpoint] PROCESS_EXEC   alice@corp.com → WKSTN-042  (dropper)
```

Both chains correctly identify alice@corp.com as the compromised account and WKSTN-042 as the compromised host. The remaining 28 events (normal activity for bob, carol, dave, eve) produce no chain alerts.

*(Note: Chains 1 and 2 share several events. In Phase 2, a deduplication step will merge overlapping chains involving the same identity and asset over the same time window into a single alert.)*

---

## 6. Edge-Case Tests and Results

All 11 tests pass (`pytest tests/ -v` → 11 passed in 0.21s).

### Test File 1: `tests/test_missing_source.py` (3 tests)
| Test | What it checks | Result |
|------|---------------|--------|
| `test_missing_endpoint_source_does_not_crash` | `EndpointAdapter.load(nonexistent_file)` returns `[]`, no exception | **PASS** |
| `test_missing_endpoint_engine_still_runs` | Full pipeline with identity-only data → 0 chains, no crash | **PASS** |
| `test_missing_identity_source_does_not_crash` | Symmetric: endpoint-only → 0 chains, no crash | **PASS** |

**Finding:** The graceful-degradation constraint is fully met. Missing either source does not crash the engine and produces no false chains.

### Test File 2: `tests/test_delayed_event.py` (3 tests)
| Test | What it checks | Result |
|------|---------------|--------|
| `test_delayed_event_outside_window_not_included_in_chain` | Endpoint event at T+45min (window=15min) → 0 chains | **PASS** |
| `test_in_window_event_is_detected` | Endpoint event at T+14min → 1 chain detected | **PASS** |
| `test_delayed_event_timestamp_is_preserved_correctly` | Normalization preserves exact timestamp, no drift | **PASS** |

**Finding:** The time-window logic is correct in both directions. Events outside the window are excluded; events inside the window are included.

### Test File 3: `tests/test_malformed_event.py` (5 tests)
| Test | What it checks | Result |
|------|---------------|--------|
| `test_adapter_rejects_event_missing_required_field` | Event without `userId` → rejected at adapter, other events still processed | **PASS** |
| `test_normalizer_raises_on_bad_timestamp` | `"NOT-A-DATE"` → `NormalizationError("Invalid timestamp")` | **PASS** |
| `test_adapter_skips_non_dict_items` | `[event, null, "string", 42, event]` → only 2 valid dicts returned | **PASS** |
| `test_unknown_event_type_mapped_to_unknown_not_rejected` | Unrecognized eventType → `event_type="UNKNOWN"`, not dropped | **PASS** |
| `test_valid_events_processed_despite_malformed_mixed_in` | 3 events (2 valid, 1 bad timestamp) → 2 CommonEvents, 1 error, no crash | **PASS** |

**Finding:** The engine is resilient to all tested malformation types. Schema drift (a renamed field) will cause rejection with a logged error, not a silent incorrect value.

---

## 7. Early Risk Register

| Risk | Likelihood | Impact | Mitigation (Phase 2) |
|------|-----------|--------|----------------------|
| R1: False correlation from coincidental timing | 4/5 | 3/5 | Require ≥2 independent signals; confidence scoring; suppression list |
| R2: Entity resolution error (wrong user → asset link) | 3/5 | 5/5 | Session-level time-bounded linking; require temporal overlap |
| R3: Missing-source blind spots | 3/5 | 4/5 | Health-check alert when source silent for N minutes; "incomplete coverage" flag |
| R4: Schema drift from upstream tool updates | 2/5 | 4/5 | Schema version validation; loud failure on missing field; CI tests against multiple schema versions |
| R5: Alert volume overwhelming SOC | 2/5 | 3/5 | Alert throttling (max N chains/identity/hour); conservative default thresholds |

---

## 8. Remaining 65% (Phase 2 and 3 Roadmap)

| Deliverable | Phase |
|------------|-------|
| Email, network, cloud adapters (3 more sources proving the full 5-source pattern) | 2 |
| Real-time webhook ingestion (replacing file-poll) | 2 |
| **Measured experiment:** run baseline + rule engine on shared dataset; compute precision, recall, time-to-detect, FP rate, error analysis | 2 |
| Session-level entity resolution to fix Risk R2 (shared workstations) | 2 |
| Config file for rule thresholds (security lead tunes without code change) | 2 |
| Rollback / change-review workflow for high-impact rule changes (proposed design already in architecture.md) | 2 |
| Alert throttling and deduplication | 2 |
| ML-based correlation (anomaly detection as a rule supplement, not replacement) | 3 |
| User guide and walkthrough for SOC analysts | 2/3 |
| Stakeholder validation session (live demo + feedback) | 3 |

The architecture, schema, and entity model designed in Phase 1 deliberately support all of these without rework. Adding a new source is one new adapter + one new field-mapping function. Adding a new rule is one new `_rule_` method in `rules.py`.
