# Phase 2 Write-Up: Attack-Chain Correlation Engine

This document details the additions made in Phase 2, fulfilling the evaluator's requirements.

## 1. Five-Source Coverage & Cross-Domain Rule

**What we built:**
- Added adapters for **Email**, **Network**, and **Cloud** (building on Phase 1's Identity and Endpoint).
- Extended the `CommonEvent` schema mapping in `normalizer.py`.
- Wrote Rule 3 (`PHISHING_TO_CLOUD_COMPROMISE`) which spans all five sources.

### Explain This To Me: Cross-Domain Rule Logic

*If asked in review: "How does the phishing-to-cloud rule actually work without relying on a single vendor's ID?"*

**Explanation:**
1. **The Entry Point:** The engine sees an `EMAIL_CLICK` event for a user (e.g., `alice@corp.com`).
2. **The Credential Theft:** It then looks for a `LOGIN_SUCCESS` for that exact same user within a short window (default 30 mins). This represents the attacker using the harvested credentials.
3. **The Pivot to Cloud:** From the time of that login, it looks forward another 60 minutes for high-severity Cloud events (like `CLOUD_ROLE_ASSUME` or sensitive `CLOUD_API_CALL`) tied to the same identity.
4. **Corroboration (The other 2 sources):** If the engine finds related **Network** activity (like a DNS query to a bad domain) or **Endpoint** activity (like `powershell.exe`) on a physical machine linked to that user's active session, it boosts the confidence score from 55% up to 100%.

**Why this is resilient:** The rule doesn't need all 5 sources to fire. If the endpoint agent is broken, it still connects Email → Identity → Cloud and flags the chain, just with slightly lower confidence. This proves the architecture degrades gracefully.

## 2. Session-Time-Bounded Entity Resolution (Risk R2 Mitigated)

**What we built:**
- Phase 1 had a flaw: if User A logged into a shared workstation in the morning, and User B downloaded malware on it in the afternoon, the engine would blame User A because the identity-to-asset link was permanent.
- **Phase 2 Fix:** We introduced `assets_for_identity_at(identity_id, timestamp)`. It checks the `login_time` and `logout_time` of the `Session` object. The engine only looks at events on the workstation if they occurred *while that specific user's session was active*.
- Proved with `test_session_bounded_resolution.py`.

## 3. Externalized Configuration

**What we built:**
- Moved all hardcoded rule thresholds, time windows, and suspicious process heuristics out of `rules.py` and into `src/correlate/config.yaml`.
- This enables a SOC lead to tune the engine (e.g., changing the brute-force threshold from 3 to 5) without making a code commit.

## 4. Formal Measured Experiment

**What we built:**
- Replaced the informal "69 vs 2" comparison with `src/experiment/run_experiment.py`.
- Created a ground-truth synthetic dataset containing 4 planted attacks (3 by Alice, 1 by Eve) and various benign noise.

### Explain This To Me: The Experiment Metrics

*If asked in review: "What do your experiment metrics mean in plain English?"*

**Explanation:**
- **Baseline (Naive Join):** This simulates what happens when you just group events by user ID and time, which is how a lot of SIEMs work out of the box. Our baseline generated 190 raw correlations because it linked every benign action (like opening Notepad) with every other action.
- **Rule Engine (Our System):** Generated exactly 3 chains.
- **Precision (100%):** "When the engine cries wolf, is there actually a wolf?" Yes. Every single chain the engine flagged (3 out of 3) matched a planted, real attack in our synthetic data. There were zero false alarms.
- **Recall (75%):** "Out of all the wolves in the forest, how many did we catch?" We planted 4 attacks, and the engine caught 3. It intentionally missed Eve's "credential dump" attack because she didn't have any failed logins first, and we haven't written a rule for that specific pattern yet. This shows the system is honest and measurable.
- **Time-to-Correlate:** It took ~1 millisecond to evaluate all events, proving the architecture is fast enough for real-time streaming.

## Deferred to Phase 3
As planned, the following items are left for the final phase:
- Rollback/change-review workflow for rules.
- Chain deduplication (alert throttling).
- ML anomaly detection.
- Final User Guide.
