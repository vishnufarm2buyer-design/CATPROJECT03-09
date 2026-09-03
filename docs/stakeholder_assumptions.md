# Stakeholder Assumptions

## 1. Who Uses This System

| Role | Responsibilities | How They Use the Engine |
|------|-----------------|------------------------|
| **SOC Analyst (Tier 1/2)** | First-line alert triage, 24×7 monitoring | Receives correlated chain alerts instead of N individual alerts; decides whether to escalate |
| **Incident Responder** | Owns active investigations, does root-cause analysis | Uses chain timeline to reconstruct attack path without manually cross-referencing 5 tools |
| **Security Lead / Manager** | Sets detection rules, owns the SOC playbook | Defines correlation rules and time-window thresholds; reviews audit trail for compliance |

**Who does NOT use this system directly:** IT helpdesk, developers, end-users.  
The engine is a backend correlation layer — it feeds into existing dashboards and ticketing systems (e.g. Splunk, ServiceNow), it does not replace them.

---

## 2. Assumed Current Workflow ("Isolated-Tool Review")

This is the baseline we are improving upon.

**Step-by-step current workflow for a suspected multi-stage attack:**

1. Identity tool (e.g., Azure AD / Okta) fires an alert: "10 failed logins for user alice@corp.com in 5 minutes."
2. A SOC Analyst opens the identity dashboard and investigates the user.
3. Separately, the endpoint tool (e.g., CrowdStrike / Defender) fires: "Suspicious PowerShell process on host WKSTN-042."
4. The analyst opens the endpoint dashboard. At this point, they do not yet know these two events are linked to the same attack chain.
5. Manual cross-referencing: analyst looks up who was logged into WKSTN-042 at that time, checks if alice@corp.com ever authenticated to that machine, and compares timestamps by eye.
6. If lucky, the analyst finds the link — but this takes **15–45 minutes** of manual pivoting and requires tool access for each system.

**Problems with this workflow:**
- Each tool produces its own alerts. A 5-source attack generates 5 separate tickets.
- The correlation step is entirely manual and analyst-skill-dependent.
- During high-volume periods (e.g., a ransomware campaign), the queue overwhelms Tier-1 analysts and correlated events get missed.
- There is no audit trail of the correlation decision itself — only the individual tool alerts.

---

## 3. Constraints

| Constraint | Details |
|-----------|---------|
| **Must not replace existing SIEM or security tools** | The engine sits alongside existing tools as an additional correlation layer. It reads from the same event feeds (via webhook or file export) and writes correlated chains back to the existing ticketing/alerting system. No tool is decommissioned. |
| **Must degrade gracefully when a source is missing or delayed** | If the network tap goes offline, correlation using the remaining 4 sources continues. Chains involving only identity + endpoint can still be detected. Missing sources are logged to the audit trail. A chain is never silently dropped because one source is unavailable. |
| **Must be explainable** | Every chain alert must carry: which rule fired, which events contributed, and what entity links were used. SOC analysts must be able to understand *why* the engine linked two events. |
| **Must not introduce high false-positive rates** | The correlation logic starts conservative (high-confidence rules only). Rule thresholds are tunable by the security lead without code changes. |
| **Must run within existing SOC infrastructure** | No mandatory cloud dependency. Runs on a standard server alongside the existing SIEM. Phase 1 uses file-based ingestion; Phase 2 adds real-time webhook ingestion. |

---

## 4. Success Definition

**Primary metric:** Earlier detection of multi-stage attack chains compared to the baseline (isolated-tool review).

| Metric | Baseline Target | Engine Target |
|--------|----------------|--------------|
| Time-to-correlate (minutes) | 15–45 min (manual) | < 1 min (automated) |
| Analyst pivots required per chain | 3–5 (one per tool) | 0 (engine does the linking) |
| Attack chains detected per shift | Depends on analyst skill and queue depth | Deterministic — any chain matching a rule is always caught |
| Audit trail completeness | None (no record of correlation reasoning) | 100% — every decision logged |

**Secondary metrics (Phase 2):**
- False-positive rate of correlated chains vs confirmed incidents
- Mean time-to-escalate after a chain alert fires
- Coverage across all 5 source domains

---

## 5. Assumptions We Are Making (to be validated in Phase 2/3)

1. **Each identity event contains a stable `identity_id`** (e.g., UPN or employee ID) that is shared across all five tools. In practice, tools may use different user identifiers — entity resolution (Phase 1 partial, Phase 2 full) will handle this.
2. **Each endpoint event contains a stable `asset_id`** (e.g., hostname or MAC address) that can be linked back to an authenticated user via session records.
3. **Time synchronization across tools is within ±5 seconds** (NTP-synced). Events from different tools that are part of the same attack chain will have timestamps close enough to correlate. The configurable time-window (default: 10 minutes) provides tolerance.
4. **The five source tools can export events** in JSON or a structured format the adapters can read. No source requires proprietary binary decoding.
5. **SOC analysts accept a new chain-alert channel** alongside their existing tool alerts. They do not need to change their existing tools, only to watch an additional feed.
