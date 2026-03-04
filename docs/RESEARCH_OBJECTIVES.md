# Research Objectives & Funding Scope (public)

This document is a **public** summary of research objectives and deliverables for IONA. It intentionally excludes any sensitive information and does not include private budgeting details.

---

## Research problem

Blockchain systems can fail in subtle ways due to:

- execution nondeterminism across environments
- unsafe protocol upgrades / migrations
- validator operational misconfiguration and adversarial network conditions

IONA investigates approaches that make these risks **measurable**, **detectable**, and **testable**.

---

## Objectives (3-month research cycle)

### Objective 1 — Deterministic replay baseline
Deliverables:
- Replay harness that re-executes historical blocks and recomputes state roots
- Divergence detection with structured logs
- CI job that runs a minimal deterministic replay test

Success criteria:
- Reproducible state roots across two independent environments for the same inputs

---

### Objective 2 — Upgrade safety simulation
Deliverables:
- ProtocolVersion transition test harness
- Schema migration validation tests
- Mixed-version simulation scenario (rolling upgrade)

Success criteria:
- Upgrade simulation completes without state divergence for defined scenarios

---

### Objective 3 — Validator hardening experiments
Deliverables:
- Peer scoring / isolation experiments (eclipse-resistance)
- Network partition simulation scenario
- Storage integrity checks (corruption detection hooks)

Success criteria:
- Clear documented failure modes + mitigation approaches

---

## Scope boundaries

Out of scope for this research cycle:
- Tokenomics / market integration
- Production mainnet launch
- Performance marketing (TPS claims)

This project prioritizes correctness, reproducibility, and safety research.

---

## Expected outputs

- Open-source code changes in this repository
- Public research notes under `docs/`
- Reproducible test scenarios (replay + upgrade simulation)
- A short final report summarizing results and limitations
