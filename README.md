# Attack-Chain Correlation Engine
## Phase 2 — Completed (Semester 5, C28)

---

## Quick Start

```bash
# 1. Clone / navigate to this directory
cd "attack-chain-correlator"

# 2. Install dependencies (PyYAML for config, pytest for testing)
pip install -r requirements.txt

# 3. Run the engine end-to-end
python -X utf8 main.py

# 4. Run the formal experiment (Benchmarks vs Baseline)
python -X utf8 src/experiment/run_experiment.py

# 5. Run all 21 tests
python -X utf8 -m pytest tests/ -v

# 6. (Optional) Regenerate synthetic data from scratch
python data/generate_samples.py
```

> **Note:** The `-X utf8` flag is needed on Windows terminals (PowerShell) to enable UTF-8 output mode.

---

## What's Built So Far (Phase 2)

**Phase 1** delivered the core pipeline: adapter pattern, common schema, entity resolution, a rule-based correlation engine, append-only JSONL audit trail, and Graceful Degradation edge-case tests.

**Phase 2** expands the system:
- **5-Source Coverage**: Added Email, Network, and Cloud adapters alongside Identity and Endpoint.
- **Cross-Domain Correlation**: Added `PHISHING_TO_CLOUD_COMPROMISE` rule spanning all 5 domains in a single attack chain.
- **Session-Time-Bounded Resolution**: Entity resolution now uses session `login_time` / `logout_time` to prevent shared-workstation false positives (mitigates Risk R2).
- **Externalized Configuration**: Rule thresholds and heuristics are loaded from `config.yaml` (editable by security leads without code changes).
- **Formal Experiment**: Benchmarks the rule engine against a naive baseline, measuring Precision (100%) and Recall (75%).

*(Phase 3 will add chain deduplication, ML anomaly detection, and a rollback workflow.)*

---

## Repo Structure

```text
attack-chain-correlator/
├── data/                         # Synthetic events (Identity, Endpoint, Email, Network, Cloud)
│   └── generate_samples.py       # Deterministic generator
├── docs/
│   ├── architecture.md           # System design & assumptions
│   ├── schema.md                 # Universal event schema
│   ├── risk_register.md          # Project risks (R2 mitigated)
│   ├── writeup.md                # Phase 1 project narrative
│   └── writeup_phase2.md         # Phase 2 walkthrough & explain-to-me addendum
├── src/
│   ├── audit/                    # Append-only ledger
│   ├── correlate/
│   │   ├── config.yaml           # Externalized rule thresholds (NEW)
│   │   ├── baseline.py           # Naive join (for experiment)
│   │   ├── chain.py              # Output models
│   │   └── rules.py              # Rule engine + 3 correlation patterns
│   ├── entity/                   # Session-bounded resolution (models.py, resolver.py)
│   ├── experiment/               # Formal performance benchmark
│   │   └── run_experiment.py
│   ├── ingest/                   # 5 Adapters (identity, endpoint, email, network, cloud)
│   └── normalize/                # normalizer.py, schema.py
├── tests/                        # 21 Pytest edge-case & functional tests
├── main.py                       # The end-to-end pipeline runner
└── requirements.txt              # Dependencies (pyyaml, pytest)
```

---

## Configuration (`config.yaml`)
Rule thresholds and heuristic lists have been externalized to `src/correlate/config.yaml`. 
Security analysts can tweak correlation windows, min failure thresholds, and suspicious processes without altering code. 
If the file is deleted, the engine falls back to hardcoded safe defaults.

## Audit Trail

Every run appends records to `audit_trail.jsonl` in this format:

```json
{"ts": "2024-11-15T08:05:30+00:00", "event_type": "RULE_FIRED", "actor": "engine",
 "detail": {"rule": "BRUTE_FORCE_ENDPOINT", "identity_id": "alice@corp.com", ...}}
```
