# Phase 2 Formal Experiment Results

## Methodology
The correlation engine was benchmarked against a naive time-window join (Baseline).
Dataset: 65 synthetic events across 5 domains (Identity, Endpoint, Email, Network, Cloud).

### Ground Truth (Planted Attacks)
1. Alice credential stuffing → endpoint compromise
2. Alice MFA bypass → endpoint compromise
3. Alice phishing → credential capture → C2 → cloud privilege escalation
4. Eve privileged recon (credential dump on Domain Controller)

**Total Planted Scenarios**: 4

---

## Results

### Target Goals
- **Precision**: ≥ 90%
- **Recall**: ≥ 75%

### Measured Performance

| Metric | Baseline (Naive Join) | Rule Engine | Result |
|--------|-----------------------|-------------|--------|
| **Total Correlations** | 190 pairs | 3 chains | |
| **False-Correlation Rate** | 24.2% (minimum) | 0.0% | Engine eliminates noise |
| **Precision** | Very Low | 100.0% | **PASS** (Target ≥ 90%) |
| **Recall** | N/A | 75.0% | **PASS** (Target ≥ 75%) |
| **Missed-Event Rate** | N/A | 25.0% | |
| **Time-to-Correlate** | 0.39 ms | 0.36 ms | Fast enough for real-time |

### Detected Chains
- **Chain 1**: `BRUTE_FORCE_ENDPOINT` (Confidence: 95%) - 8 events spanning endpoint, identity
- **Chain 2**: `MFA_BYPASS_COMPROMISE` (Confidence: 85%) - 5 events spanning endpoint, identity
- **Chain 3**: `PHISHING_TO_CLOUD_COMPROMISE` (Confidence: 100%) - 12 events spanning cloud, email, endpoint, identity, network

---

## Error Analysis

**Why is Recall 75% (and not 100%)?**
The engine successfully detected all 3 of Alice's attack chains, including the cross-domain phishing-to-cloud compromise.
However, **Eve's credential dump on the Domain Controller was missed.**

**Root Cause:**
Currently, our rules depend on either a failed login sequence (Rule 1) or an MFA bypass (Rule 2) as the trigger. Eve's attack used a single, successful privileged login followed directly by `mimikatz.exe`. The engine lacks a rule for "Privileged Recon without prior authentication failure".

**Next Steps (Phase 3):**
Create a new rule (`PRIVILEGED_RECON_COMPROMISE`) that monitors `is_privileged=True` identities for high-severity endpoint/cloud actions immediately following normal logins.
