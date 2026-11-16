# Architecture and Boundaries: ClusterGuard

## Overview

ClusterGuard has one target user: an SRE, DevOps engineer, or cloud infrastructure operator. One mission: orchestrate credible microservice and AI workload allocations under strict node quotas and security compliance constraints, and independently verify what autonomous agentic mutations actually changed. The IntentProof engine serves as an internal verification and mutation testing harness.

## Typed Agent Flow

```mermaid
flowchart TD
 U[SRE / Cluster Operator] --> N[Workload Intent / Quotas / Security Policies]
 N --> Q[Server-only Advisory AI: Groq Primary / Gemini Fallback]
 Q --> S[Placement Affinity Heuristic Normalization]
 S --> C[Admission Controller & Compliance Filter]
 N --> C
 C --> O[Bounded Deterministic Greedy Scheduler]
 O --> W[Cryptographic Consequence Contract SHA-256 Hash]
 W --> A{Human Approval Gate?}
 A -->|No| STOP[Zero Cluster State Changes]
 A -->|Yes| X[Simulated Cluster Orchestrator]
 X --> ACK[Control Plane Ack 200 OK - Untrusted]
 X --> R[Independent Observed Telemetry Readback]
 R --> V[Independent Outcome Verifier]
 W --> V
 V --> E[Evidence Receipt PASS/BLOCK/UNKNOWN]
 E --> T[IntentProof Formal Mutation Testing]
 E --> H{Recovery Approved?}
 H -->|Yes, only verified zombie ack| REPAIR[Bounded One-Shot Recovery Cycle]
 REPAIR --> R
```

## Contracts

`clusterguard.contract.v1` contains scheduled workload IDs and instance counts, expected remaining cluster quotas (vCPU, GPU, RAM, NVMe, Egress, Static IPs), protected security invariants (`iam_privilege_escalation.locked`, `kernel_ebpf_sandbox.enforced`), human approval requirement, observation requirement, and a one-attempt recovery budget. Each plan includes a SHA-256 notary hash of the canonical contract. The command response and observed node state are strictly decoupled. The independent verifier checks pod allocations, quota balances, security invariants, contract hash, non-negative capacity, and unexpected state drift. Missing readback produces `UNKNOWN`, never a false `PASS`.

## Interoperability

- `LLMClient`: Calls **Groq** (`openai/gpt-oss-120b` or `llama-3.3-70b-versatile`) as the primary fast reasoning engine, and automatically falls back to **Google Gemini** (`gemini-3.8-flash`) on rate limit, downtime, or missing Groq credential. An HTTP 503 is returned if both providers fail in live mode—**no silent synthetic fallback**.
- `scheduler`: Converts placement affinity tags into **heuristic ranking** across compliant workloads; checks finite node quotas and explicit compliance policies before scheduling instances.
- `IntentProof`: Mutation audit exercises modeled contract invariants and detects unauthorized privilege side-effects (achieving 100% mutant kill rate).
- `HTTP`: Minimal same-origin JSON endpoints; server-side session token, bounded request sizes, per-IP rate-limiting, process-level live request limits, restrictive static-file routing, and strict CSP security headers.

## Assurance Limitations

Source integrity SHA-256 certifies self-consistency against the pre-declared contract; it does not establish hardware HSM provenance. In-process simulation demonstrates contract verification and guardrails without modifying physical cloud data centers.
