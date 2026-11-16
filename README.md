# ClusterGuard

**Deterministic Contract Verification & Guardrail Harness for Autonomous Infrastructure Agents**

> *"Don't trust the control plane acknowledgment — verify the physical node state."*

Autonomous infrastructure agents (powered by LLMs and DevOps orchestration tools) present a catastrophic reliability problem: **false success**. A cloud API or agent reports `HTTP 200 SUCCESS {"status": "Created"}` while pods crash-loop, cluster quotas fail to commit, or security policies leak.

**ClusterGuard** is an enterprise-grade agentic guardrail harness that solves the false-success problem through **deterministic greedy scheduling, pre-declared cryptographic consequence contracts (SHA-256), and independent post-execution state verification**.

```
[SRE Intent & Quotas]
        │
        ▼
[Advisory AI Boundary] ──(Groq / Gemini)──> Proposes Heuristic Topology (CANNOT waive quotas)
        │
        ▼
[Deterministic Scheduler] ───────────────> Bounded Packing (vCPU, GPU, RAM, NVMe, Security)
        │
        ▼
[Cryptographic Contract] ────────────────> SHA-256 Pre-Declared Invariant Lock
        │
        ▼
[Human Authorization Gate] ─────────────> Explicit Sign-Off Before Mutation
        │
        ▼
[Simulated Infrastructure] ──────────────> Control Plane Ack (ALWAYS claims "SUCCESS")
        │
        ▼
[Independent Verifier] ──────────────────> Compares Real Telemetry vs Contract -> PASS | BLOCK | UNKNOWN
        │
        ▼
[IntentProof Mutation Engine] ───────────> 100% Mutant Kill Rate (Tested Guardrails)
```

---

## Architectural Highlights

| Pillar | Implementation | Technical Advantage |
|---|---|---|
| **Zero-LLM Control Loop** | Pure deterministic greedy bin-packer (`clusterguard/agent.py`) | Mathematically bounded; reproducible; zero hallucinated allocations. |
| **Strict Trust Boundary** | Advisory LLM (`Groq` Llama 3.3 / GPT-OSS + `Gemini` fallback) | AI advises on placement affinity; cannot override quotas, budgets, or security rules. |
| **Pre-Declared Contracts** | `clusterguard.contract.v1` hashed with SHA-256 before execution | Tamper-evident post-state promises locked before any simulated mutation. |
| **Independent 3-Valued Verifier** | Verifies observed telemetry against contract | Returns `PASS` (exact match), `BLOCK` (disagreement), or `UNKNOWN` (telemetry blackout). |
| **Zombie Ack Detection** | Hero Ack vs Verifier split-panel | Exposes the contradiction when the control plane reports `200 OK` but physical state fails. |
| **Bounded Self-Repair** | Single recovery cycle for recoverable false successes | Requires secondary human authorization; forbids retry loops on privilege leaks. |
| **IntentProof Mutation Audit** | Formal mutation testing engine (`intentproof/`) | Deliberately corrupts post-state to prove verifier catches 100% of injected faults. |

---

## Quick Start (Zero Dependencies, Offline Heuristics Mode)

Requirements: **Python 3.11+ standard library only** (no `pip install` required, zero external dependencies).

```bash
# Start ClusterGuard
python -m clusterguard.server
```

Open **`http://127.0.0.1:8765`** in your browser to access the SRE Cockpit.

---

## Live Advisory AI Configuration (Groq Primary + Gemini Fallback)

To enable live multi-model LLM advisory inference, set environment variables:

```bash
# Primary fast LLM: Groq
export GROQ_API_KEY="gsk_..."
export GROQ_MODEL="openai/gpt-oss-120b"

# Fallback LLM: Google Gemini
export GEMINI_API_KEY="AQ..."
export GEMINI_MODEL="gemini-3.8-flash"

export LLM_LIVE_ENABLED="1"
export MAX_LIVE_PLANS="50"

python -m clusterguard.server
```

---

## Automated Test Suite

ClusterGuard features exhaustive automated tests covering deterministic scheduling, compliance enforcement, contract hashing, fault detection, and mutation assurance:

```bash
# Run ClusterGuard and Core Agent test suites (32 tests)
python -m unittest tests/test_clusterguard.py -v

# Run IntentProof formal warranty mutation tests (33 tests)
PYTHONPATH=intentproof/src python -m unittest discover -s intentproof/tests -v
```

---

## The 4 Injected Fault Scenarios

1. **Nominal Deployment (`none`)**: Clean orchestration. Observed state matches contract identically -> **`PASS`**.
2. **Zombie Ack (`false_success`)**: Control plane reports `HTTP 200 SUCCESS`, but physical nodes are untouched and quotas uncommitted -> **`BLOCK`** (Recoverable with secondary human approval).
3. **Privilege Leak (`unexpected_side_effect`)**: Microservices provisioned, but IAM privilege escalation lock was flipped to unlocked -> **`BLOCK`** (Fatal security breach; automated recovery strictly forbidden).
4. **Telemetry Blackout (`missing_observation`)**: Observability probe times out / network split-brain -> **`UNKNOWN`** (Never assume success when telemetry cannot be read).

---

## Enterprise SRE Cockpit Features

- **11-Stage Workflow Stepper**: `Intent` → `Advisory AI` → `Policy Filter` → `Affinity Scoring` → `Resource Packing` → `Contract Lock` → `Approval Gate` → `Execution` → `Verification` → `Recovery` → `Formal Proof`.
- **Live Cluster Shelf**: Real-time capacity gauges for `vCPU`, `H100 GPU`, `RAM GiB`, `NVMe Storage`, `Egress Bandwidth`, and `Static IPs`.
- **Hero Ack vs Verifier Split Card**: Visual alarm highlighting control plane false acknowledgements.
- **Before vs Expected vs Observed Diff Table**: Mismatched resources highlighted in pulsating red.
- **Formal Assurance Suite**:
  - `AI vs Baseline`: Counterfactual ablation proving advisory AI isolation.
  - `50% Quota Shock`: Elasticity test under severe supply contraction.
  - `IntentProof Mutation Audit`: Matrix of killed vs survived mutant invariants (100% kill rate).
  - `Cryptographic Receipt`: SHA-256 notary validation and downloadable JSON audit receipt.
- **Beginner & Technical Modes**: Toggle between high-level SRE summaries and raw JSON telemetry inspection.
- **Interactive Tour**: 6-step guided walkthrough with automated actions.

---

## Production Deployment

### Docker Container
```bash
docker build -t clusterguard .
docker run -p 8765:8765 clusterguard
```

### Render Blueprint
Deploy directly to Render via the included `render.yaml` manifest. Standard health checks are available at `/healthz`.
