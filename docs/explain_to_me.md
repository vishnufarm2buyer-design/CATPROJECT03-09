# "Explain This To Me" — Module-by-Module Study Guide

> Read this before your review session. Each section gives you a plain-English
> explanation of what the module does, *why* it was built that way, and the
> 2–3 questions a reviewer is most likely to ask you about it.

---

## Module 1: `src/ingest/base_adapter.py` — The Abstract Base Adapter

### What it does
This is a **template** for all source adapters. It defines the contract: every adapter must have a `source_name` (e.g., `"identity"`) and a list of `_required_fields`. The `load()` method is shared across all adapters — it opens the JSON file, skips malformed entries, and returns a clean list.

### Why it's built this way
Without a base class, each adapter would have its own file-reading + error-handling code. If we change how we handle missing files, we'd have to update five adapters. With a base class, the change happens once.

The key design choice is: **missing file = empty list, not crash**. This is the graceful degradation requirement.

### Reviewer questions you should be able to answer
1. *"What happens if the identity source file is missing?"* → The adapter logs a WARNING and returns `[]`. The caller (main.py) continues with zero identity events. No exception is raised.
2. *"What if an event is in the file but missing a required field?"* → That specific event is skipped and logged. The remaining valid events are returned. One bad event doesn't abort the whole file.
3. *"Why use an abstract base class instead of a simple function?"* → Because all 5 sources follow the same pattern. If we add a Phase 2 source, it just subclasses BaseAdapter — it gets `load()` for free and only needs to declare its own `source_name` and `_required_fields`.

---

## Module 2: `src/normalize/schema.py` + `normalizer.py` — The Common Schema

### What it does
`schema.py` defines `CommonEvent` — a single Python dataclass that all events are converted into. Every field is typed. `normalizer.py` does the mapping from source-specific format to `CommonEvent`.

**Before normalization:** An identity event looks like `{"userId": "alice@corp.com", "eventType": "LOGIN_FAILED", "riskLevel": "high", ...}`.
**After normalization:** It's a `CommonEvent(identity_id="alice@corp.com", event_type="LOGIN_FAILED", severity="high", source="identity", timestamp=datetime(...), ...)`.

### Why it's built this way
Different tools use different field names for the same concepts. `userId` (identity) vs `loggedOnUser` (endpoint) are both "who did this." If the correlation engine had to know each tool's field names, adding a new source would require changing the correlation code. With normalization, adding a source requires only one new mapping — the rest of the pipeline is untouched.

The `raw_payload` field stores the original unmodified event. This is a safety net: if normalization ever has a bug and drops a field, we can re-process from `raw_payload` without going back to the source tool.

### Reviewer questions
1. *"Why are `identity_id` and `asset_id` optional?"* → Not every event has both. A network flow event has no associated user; a cloud API call may have no source device. Making them `None` instead of omitting them makes missing data explicit — code downstream always knows to check for `None` rather than getting a `KeyError`.
2. *"What happens if you get an unknown `eventType` from the tool?"* → It maps to `"UNKNOWN"` in `CommonEvent.event_type`. The event is still ingested and processed. We don't reject it — tools often add new event types that we haven't catalogued yet, and we don't want to silently drop them.
3. *"Why store `raw_payload`?"* → Audit trail and re-processing safety. If a normalization bug drops a field, we can replay from raw without re-ingesting.

---

## Module 3: `src/entity/resolver.py` — Entity Resolution

### What it does
Scans all `CommonEvent` objects and builds a **two-way map**: for each `identity_id`, which `asset_id`s has it been seen on? And vice versa. It also creates `Session` records from login events that have both an identity and an asset.

**Example:** Alice's `LOGIN_SUCCESS` event has `identity_id="alice@corp.com"` and `asset_id="WKSTN-042"`. The resolver records: alice → {WKSTN-042} and WKSTN-042 → {alice}. Now when the rule engine sees suspicious events on WKSTN-042, it knows alice is linked to that machine.

### Why it's built this way
Without entity resolution, the rule engine could only link events that share the exact same `identity_id` AND `asset_id`. But a brute-force attack produces identity events with `asset_id=None` (the attack happens from outside before login), and endpoint events with `identity_id="alice"` and `asset_id="WKSTN-042"`. Entity resolution bridges that gap: "alice was seen on WKSTN-042 at login time, so endpoint events on WKSTN-042 belong to alice's chain."

### Reviewer questions
1. *"What if alice logged into multiple machines?"* → `assets_for_identity("alice@corp.com")` returns a **set** of all machines. The rule engine checks all of them. This is a known limitation (Risk R2): if the attack is on machine B but alice was also on machine C (unrelated), both get checked. Phase 2 fixes this with session time bounds.
2. *"How are sessions created?"* → A `Session` record is created whenever there's an `identity` source event with `event_type="LOGIN_SUCCESS"` that has both `identity_id` and `asset_id`. The session ID comes from the raw event if available, or is auto-generated.
3. *"What if the identity tool doesn't include a device ID in the login event?"* → Then `asset_id=None` and no session is created for that login. The resolver won't link that identity to any asset from that event. We'd need an endpoint event that has `loggedOnUser` set to create the link instead.

---

## Module 4: `src/correlate/baseline.py` — The Naive Baseline

### What it does
Groups events by `identity_id`, then finds all **pairs** of events that are within 10 minutes of each other. Returns every such pair as a "correlation." This is the simplest possible correlation: same user + close in time = correlated.

On our 30-event sample: **69 pairs returned**. Most are false positives.

### Why it exists
This is the **comparison point** for Phase 2's experiment. We need to prove that our rule-based engine is better than the naive approach. To do that fairly, we run both on the same data and compare. The baseline simulates what a human analyst does when they see the same username in two different tool alerts and assume they must be related.

### Reviewer questions
1. *"Why does the baseline produce 69 results when the rule engine only finds 2?"* → Because the baseline has no concept of "attack pattern." It treats alice's failed logins + her eventual login + her normal endpoint activity as all correlated. It can't distinguish "attack sequence" from "normal user activity that happens to be close in time."
2. *"Is the baseline useless then?"* → No. It's the measurement baseline. In Phase 2, we use it to calculate the false-positive rate: of the 69 naive correlations, how many correspond to real attacks? Of the 2 rule-based chains, how many correspond to real attacks? That comparison is the core of the measured experiment.
3. *"Why is the baseline in a separate module from the rule engine?"* → To keep the comparison clean. If they were in the same module, it would be tempting to have them share logic, which would corrupt the comparison. The baseline must be as simple as possible, not benefit from rule-engine improvements.

---

## Module 5: `src/correlate/rules.py` — The Rule Engine

### What it does
Implements correlation logic that understands attack *patterns*, not just coincidental timing. Two rules are implemented:

**Rule 1 — BRUTE_FORCE_ENDPOINT:**
- Finds identities with ≥3 failed logins within 10 minutes
- Checks if there's a suspicious endpoint event on a linked asset within 15 minutes of the last failure
- If both conditions are met, creates a chain

**Rule 2 — MFA_BYPASS_COMPROMISE:**
- Finds `LOGIN_SUCCESS` followed within 5 minutes by `MFA_BYPASS` for the same identity
- Checks for suspicious endpoint events on linked assets within 15 minutes
- If both conditions are met, creates a chain

Rules are **auto-discovered**: any method named `_rule_*` is automatically included in the evaluation. Adding Rule 3 in Phase 2 requires only adding a `_rule_X` method — the `run()` method picks it up automatically.

### Confidence scoring
Each rule computes a confidence score (0.0–1.0):
- Brute force: base 0.60 + bonus for extra failures + bonus for critical severity endpoint events
- MFA bypass: base 0.75 (MFA bypass is a high-signal event by itself)

### Reviewer questions
1. *"Why rule-based and not ML?"* → Three reasons: (1) rules are explainable — you can tell a SOC analyst exactly why a chain fired; (2) rules don't need training data, which we don't have yet; (3) Phase 1's baseline data IS the training data for Phase 2's ML work. You need the baseline before you can train anything.
2. *"What makes an endpoint event 'suspicious'?"* → The `_is_suspicious_endpoint_event()` helper checks: severity is high/critical (tool's own assessment), OR the process name is in a known-bad list (mimikatz.exe, svchost32.exe with non-standard path), OR the command line contains known-bad patterns (-enc, sekurlsa::, net user /domain). This is heuristic and intentionally conservative.
3. *"Could two rules fire on the same event set?"* → Yes, and that's intentional. Chains 1 and 2 in our output both involve alice, and they share some events. In Phase 2, chain deduplication will merge overlapping chains that involve the same identity over the same time window.

---

## Module 6: `src/audit/writer.py` — The Audit Trail

### What it does
Writes one JSON record per line to `audit_trail.jsonl` for every significant decision:
- `INGESTION_SUCCESS` / `INGESTION_ERROR` — what was loaded, what failed
- `ENTITY_RESOLVED` — which identity was linked to which assets
- `RULE_FIRED` — which rule matched, which events contributed
- `CHAIN_CREATED` — final chain was assembled
- `NORMALIZATION_ERROR` — a specific event was rejected

Records are **append-only** — no record is ever modified or deleted.

### Why it's built this way
**Compliance:** In a real SOC, you need evidence of what the system detected and when. If the engine flags alice as compromised and she turns out to be innocent, you need to show the exact decisions that led to the alert.

**Debugging:** If a rule fires on a false positive, you grep for the chain_id in `audit_trail.jsonl` and see exactly which events contributed and why.

**JSONL format** (one JSON object per line) is used because: it's append-safe (no need to re-parse and re-write the whole file), it's grep-friendly, and it requires no database.

### Reviewer questions
1. *"Why not use a database for the audit trail?"* → No dependency to install or configure. A file works reliably, is universally readable, and satisfies the append-only requirement. Phase 2 can add a database export if compliance requires structured querying.
2. *"What does 'append-only' actually mean in code?"* → The file is always opened with mode `"a"` (append). Each `log()` call writes one line and closes the file. There's no `"w"` (overwrite) or in-place modification anywhere in the audit writer.
3. *"How would a SOC analyst use this in practice?"* → `grep "alice@corp.com" audit_trail.jsonl` to see all decisions involving alice. `grep "RULE_FIRED" audit_trail.jsonl | python -m json.tool` to see all rules that fired with pretty-printed detail. In Phase 2, a simple web dashboard will read and display this.

---

## The Big Picture: How It All Fits Together

```
main.py calls:
  IdentityAdapter.load()    → list of raw dicts
  EndpointAdapter.load()    → list of raw dicts ([] if offline)
         ↓
  normalize(raw, "identity") → CommonEvent  (×15)
  normalize(raw, "endpoint") → CommonEvent  (×15)
         ↓
  EntityResolver.ingest(events)  → builds identity<->asset map
         ↓
  naive_join(events)         → 69 raw pairs  (baseline)
  RuleEngine.run(events, resolver) → 2 CorrelationChains
         ↓
  AuditWriter.log_*(...)    → audit_trail.jsonl
  print chain summaries     → stdout
```

The key architectural insight: **every layer only knows the format of its input and output**. The rule engine never looks at raw tool-specific dicts. The entity resolver never looks at correlation rules. This separation is what makes it extensible: adding source 3 (email) only touches the ingest and normalize layers.
