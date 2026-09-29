# Risk Register

> **Phase 2 — 5 risks identified. Likelihood and Impact rated 1–5.**
> **Updated: R2 mitigated in Phase 2 via session-time-bounded entity resolution.**

| # | Risk | Likelihood | Impact | Status | Description | Mitigation |
|---|------|-----------|--------|--------|-------------|------------|
| R1 | **False correlation from coincidental timing** | 4 | 3 | Open — Phase 3 | Two unrelated events fall within the same time window and match a rule pattern, producing a false chain alert. | Phase 3: chain deduplication, alert throttling, suppression lists for known-good scheduled activity. |
| R2 | **Entity resolution errors (wrong identity <-> asset link)** | 3 | 5 | **MITIGATED** | A user logs into a shared workstation. The engine links that user to subsequent suspicious process events started by a different user session. | **Fixed in Phase 2:** `assets_for_identity_at()` uses session login_time/logout_time to constrain linking. Test `test_session_bounded_resolution.py` proves the fix: User A's expired session no longer matches events during User B's session on the same asset. |
| R3 | **Missing-source blind spots** | 3 | 4 | Open — Phase 3 | If a source is offline, attack chains requiring that source go undetected. The engine degrades gracefully (no crash) but the attack is silently missed. | Phase 3: health-check alert when a source has not produced events in N minutes. Flag chains as "incomplete coverage" when >=1 source is missing. |
| R4 | **Schema drift from upstream tools** | 2 | 4 | Open — Phase 3 | A security tool updates its export format (renames a field). The adapter silently fails to map the field. | Phase 3: schema version validation at adapter layer. Fail loudly (logged error + audit entry). Adapter unit tests against both old and new schema versions. |
| R5 | **Alert volume overwhelming the SOC** | 2 | 3 | Open — Phase 3 | If correlation rules are tuned too sensitively, the engine generates more alerts than isolated-tool review. | **Partially mitigated in Phase 2:** rule thresholds moved to config.yaml so security lead can tune without code changes. Phase 3: implement alert throttling (max N chains per identity per hour). |

---

## Risk Matrix

```
Impact
  5 |       R2*
  4 |  R4       R3
  3 |       R1       R5
  2 |
  1 |
    +--1----2----3----4----5--> Likelihood

  * R2 mitigated — residual risk reduced to L=1, I=2 (session-bounded resolution)
```

**Phase 2 mitigation summary:**
- **R2**: Mitigated via `assets_for_identity_at()` with configurable `max_session_hours`
- **R5**: Partially mitigated via externalized config.yaml thresholds

**Priority order for Phase 3 mitigation:** R3 → R4 → R1 → R5
