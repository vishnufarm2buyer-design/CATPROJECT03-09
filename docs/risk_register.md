# Early Risk Register

> **Phase 1 — 5 risks identified. Likelihood and Impact rated 1–5.**

| # | Risk | Likelihood | Impact | Description | Planned Mitigation (Phase 2) |
|---|------|-----------|--------|-------------|------------------------------|
| R1 | **False correlation from coincidental timing** | 4 | 3 | Two unrelated events (e.g., a scheduled backup process + a routine login) happen to fall within the same time window and match a rule pattern, producing a false chain alert. High likelihood because time-window matching is imprecise. | Require ≥2 independent signals per rule (not just time + user). Add a confidence score based on the number of corroborating events. Introduce a "suppression list" for known-good scheduled activity. |
| R2 | **Entity resolution errors (wrong identity ↔ asset link)** | 3 | 5 | A user logs into a shared workstation. The engine links that user to subsequent suspicious process events on the same machine — but the process was started by a different user session on the same asset. Impact is HIGH because this can falsely implicate an innocent user in a chain. | Use session-level linking (Session entity table, Phase 2) instead of just asset-level linking. Require temporal overlap of the session with the suspicious event. |
| R3 | **Missing-source blind spots** | 3 | 4 | If the network or cloud source is offline, attack chains that require those sources (e.g., data exfiltration to cloud) are not detectable. The engine will not generate a false alert — but the attack goes undetected. Silent failure is harder to notice than a noisy one. | Emit a health-check alert when a source has not produced events in N minutes. Provide per-source availability dashboard. Flag chains as "incomplete coverage" when ≥1 source is missing. |
| R4 | **Schema drift from upstream tools** | 2 | 4 | A security tool updates its export format (e.g., renames a field from `userId` to `user_id`). The adapter silently fails to map the field. Events are then ingested with `identity_id = null`, breaking entity resolution. | Add schema version validation at the adapter layer. Fail loudly (logged error + audit entry) rather than silently dropping the field. Adapter unit tests run in CI against both old and new schema versions. |
| R5 | **Alert volume overwhelming the SOC** | 2 | 3 | If correlation rules are tuned too sensitively (low thresholds), the engine generates more chain alerts than isolated-tool review did — defeating its purpose. | Implement alert throttling (max N chains per identity per hour). Default thresholds set conservatively (Phase 1). Security lead can tune without code changes via a config file. |

---

## Risk Matrix

```
Impact
  5 |       R2
  4 |  R4       R3
  3 |       R1       R5
  2 |
  1 |
    +--1----2----3----4----5--→ Likelihood
```

**Priority order for Phase 2 mitigation:** R2 → R3 → R4 → R1 → R5
