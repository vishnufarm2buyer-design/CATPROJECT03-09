# Attack-Chain Correlation Engine
## Phase 1 — 35% Completion (Semester 5, C28)

---

## Quick Start

```bash
# 1. Clone / navigate to this directory
cd "attack-chain-correlator"

# 2. Install test dependency (only pytest — engine has no runtime dependencies)
pip install pytest

# 3. Run the engine end-to-end
python -X utf8 main.py

# 4. Run all tests
python -X utf8 -m pytest tests/ -v

# 5. (Optional) Regenerate synthetic data from scratch
python data/generate_samples.py
```

> **Note:** The `-X utf8` flag is needed on Windows terminals (PowerShell) to enable UTF-8 output mode.

---

## What This Is

A correlation engine that links security events from disconnected tools across
**identity** and **endpoint** domains, detects multi-stage attack chains using
rule-based logic, and writes every decision to an append-only audit trail.

This is Phase 1 of 3. It proves the core architectural pattern end-to-end with
2 of the 5 planned sources, synthetic data, and 2 correlation rules.

---

## Repo Structure

```
attack-chain-correlator/
│
├── docs/
│   ├── stakeholder_assumptions.md  ← Who uses this, constraints, success definition
│   ├── architecture.md             ← Mermaid diagram + written walkthrough
│   ├── schema.md                   ← CommonEvent + entity table schemas
│   └── risk_register.md            ← 5 risks with likelihood/impact/mitigation
│
├── data/
│   ├── identity_events.json        ← 15 synthetic identity events (5 users)
│   ├── endpoint_events.json        ← 15 synthetic endpoint events (6 hosts)
│   └── generate_samples.py         ← Reproducible data generator
│
├── src/
│   ├── ingest/
│   │   ├── base_adapter.py         ← Abstract adapter (missing-source safe)
│   │   ├── identity_adapter.py     ← Identity tool adapter
│   │   └── endpoint_adapter.py     ← Endpoint tool adapter
│   │
│   ├── normalize/
│   │   ├── schema.py               ← CommonEvent dataclass (the unified schema)
│   │   └── normalizer.py           ← Source-specific field mapping
│   │
│   ├── entity/
│   │   ├── models.py               ← Identity, Asset, Session dataclasses
│   │   └── resolver.py             ← identity_id <-> asset_id linker
│   │
│   ├── correlate/
│   │   ├── baseline.py             ← Naive join baseline (comparison point)
│   │   ├── rules.py                ← Rule engine (2 rules)
│   │   └── chain.py                ← CorrelationChain output object
│   │
│   └── audit/
│       └── writer.py               ← Append-only JSONL audit trail
│
├── tests/
│   ├── test_missing_source.py      ← Edge case: source file offline
│   ├── test_delayed_event.py       ← Edge case: event outside time window
│   └── test_malformed_event.py     ← Edge case: bad/incomplete event data
│
├── main.py                         ← End-to-end runner
├── requirements.txt                ← pytest only (stdlib for runtime)
└── README.md                       ← This file
```

---

## What Phase 1 Does (35% Complete)

| Component | Status | Notes |
|-----------|--------|-------|
| Identity source adapter | Done | Reads identity_events.json |
| Endpoint source adapter | Done | Reads endpoint_events.json |
| Normalization to CommonEvent | Done | Field mapping + UTC timestamp parsing |
| Entity resolution (identity <-> asset) | Done | Session-based linking |
| Naive baseline | Done | 69 raw correlations on sample data |
| Rule 1: Brute Force + Endpoint | Done | Fires correctly on alice@corp.com |
| Rule 2: MFA Bypass + Endpoint | Done | Fires correctly on alice@corp.com |
| Audit trail (JSONL) | Done | Written to audit_trail.jsonl |
| 3 edge-case tests | Done | 11 tests, all pass |
| Stakeholder assumptions doc | Done | docs/stakeholder_assumptions.md |
| Architecture diagram | Done | docs/architecture.md (Mermaid) |
| Data schema | Done | docs/schema.md |
| Risk register | Done | docs/risk_register.md (5 risks) |

---

## Phase 2 (Remaining 65%)

| Item | Phase |
|------|-------|
| Email, network, cloud adapters (3 more sources) | Phase 2 |
| Real-time webhook ingestion | Phase 2 |
| Measured experiment: baseline vs rule engine (FP rate, time-to-detect) | Phase 2 |
| Session-level entity resolution (fixes Risk R2 — shared workstations) | Phase 2 |
| Config file for rule thresholds (no-code tuning) | Phase 2 |
| Rollback / change-review workflow for rules | Phase 2 |
| ML-based correlation (complement to rule engine) | Phase 3 |
| User guide and stakeholder validation session | Phase 2/3 |
| SIEM webhook output integration | Phase 2 |
| Alert throttling / deduplication | Phase 2 |

---

## Audit Trail

Every run appends records to `audit_trail.jsonl` in this format:

```json
{"ts": "2024-11-15T08:05:30+00:00", "event_type": "RULE_FIRED", "actor": "engine",
 "detail": {"rule": "BRUTE_FORCE_ENDPOINT", "identity_id": "alice@corp.com", ...}}
```

To inspect it: `cat audit_trail.jsonl` or grep for specific events:
```bash
# Find all chain creation events
grep "CHAIN_CREATED" audit_trail.jsonl

# Find all decisions about alice
grep "alice@corp.com" audit_trail.jsonl
```
