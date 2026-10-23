# Executable Assurance — Reference Architecture

> *"Knowing how to fly does not give a pilot clearance to take off. AI systems are the same: what a model can do is capability; what it may do is authority."*

Executable Assurance establishes the architectural separation of runtime authority from model execution. AI models propose actions; an independent, fail-closed governance runtime evaluates policy, verifies cryptographically qualified evidence, checks real-time identity and licensing, and issues single-use permits bound to exact output bytes before any consequential effect can reach external infrastructure.

This repository provides the open-source reference implementation accompanying the published foundational research by **Ernest Chiweshe**:

- **Paper A (Foundational Position Paper & Specification):**  
  [**Capability Is Not Authority: Executable Assurance as Infrastructure for Containing AI Risk to Humankind**](https://doi.org/10.5281/zenodo.23580975)  
  *Ernest Chiweshe, 22 October 2026. DOI: 10.5281/zenodo.23580975*

- **Paper B (Technical Architecture & Empirical Evidence):**  
  [**Governed AI as Runtime Infrastructure: A Unified Authority and Evidence Architecture for Regulated Agentic Systems**](https://doi.org/10.5281/zenodo.23581016)  
  *Ernest Chiweshe, 22 October 2026. DOI: 10.5281/zenodo.23581016*

---

## The Core Principles

1. **Capability Is Not Authority:** An agent's technical ability to execute an action does not constitute permission. All actions require independently verified authorization outside the agent loop.
2. **Single-Path Fail-Closed Door:** There is only one path to external side-effects. If the governance runtime halts, loses state, or refuses, the door remains closed.
3. **The Permit Is a Single-Use Boarding Pass:** Authorization is not a blanket API token or role. A permit is cryptographically bound to one tenant, one specific target, the exact output bytes, and an expiring validity window, usable exactly once. Replay attempts are instantly rejected.
4. **Evidence Before Effect:** No action is permitted until the decision, policy evaluation, and qualification signatures are committed to an immutable append-only ledger.
5. **Refusals Are Authoritative Evidence:** Every blocked attempt, replayed permit, or policy refusal is signed and stored with equal weight to approvals, providing a complete regulatory audit trail.
6. **Consequence-Tiered Human Oversight:** Human-in-the-loop approval is triggered automatically based on evaluated consequence tiers, preserving human agency while preventing cognitive fatigue.

---

## What This Repository Contains

This standalone reference architecture provides:

- **The Regulated Core (`regulated_core/`):** The domain-agnostic, fail-closed authority engine implementing the Six-Ring Assurance Architecture (Rings 1–2).
- **The Production Gate & Ledger (`factory/`):** Cryptographic verification contracts, single-use permit enforcement, and tamper-evident decision logging.
- **Verification & Test Suite (`tests/`):** 2,837 automated tests verifying single-path isolation, replay prevention, qualification checks, and fault injection drills.
- **Empirical Soak Evidence (`evidence/soak-2026-07/`):** Verifiable logs from the 24-hour CloudHSM soak evaluation (854,100 consecutive governed decisions across 2,847 batches with zero failures).

---

## Quickstart & Replication

### 1. Installation

```bash
# Clone the reference repository
git clone https://github.com/ernest-chiweshe/executable-assurance-reference.git
cd executable-assurance-reference

# Create and activate an isolated virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies and the package
pip install -e .
```

### 2. Running the Test Suite

```bash
# Execute the public test suite
pytest tests/
```

---

## Walkthrough Videos & Media

A companion library of architecture walkthroughs, technical deep-dives, and documentary films is available at:  
👉 **[https://www.lumiwright.com/videos](https://www.lumiwright.com/videos)**

- **Flagship Film:** *One Door: Why Capability Is Not Authority in Autonomous AI* (14-min documentary)
- **Official Trailer:** *Executable Assurance in 3 Minutes*
- **Technical Series:** Topic-by-topic breakdowns of key custody, runtime topology, and evidence verification.

---

## Author & Contact

**Ernest Chiweshe**  
Founder & CEO, LumiWright  

- **Email:** [ernest.chiweshe@lumiwright.com](mailto:ernest.chiweshe@lumiwright.com)
- **LinkedIn:** [linkedin.com/in/ernest-chiweshe-6b7732433](https://www.linkedin.com/in/ernest-chiweshe-6b7732433/)
- **YouTube:** [youtube.com/@ExecutableAssurance](https://www.youtube.com/@ExecutableAssurance)
- **X / Twitter:** [@ernest_chiweshe](https://x.com/ernest_chiweshe)

---

## Licensing

- **Software & Implementation:** Licensed under the [Apache License, Version 2.0](LICENSE).
- **Research Papers:** Published under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/), as deposited on Zenodo.
