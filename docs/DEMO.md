# Interactive Product Walkthrough: ClusterGuard

1. **The Problem (10 seconds):** Autonomous infrastructure agents and cloud APIs frequently suffer from the "false success" failure mode: reporting command success while physical node allocations drift, pods crash-loop, or security policies leak.
2. **Advisory AI Topology Heuristics (30 seconds):** Select **Live AI** (powered by Groq with automatic Gemini fallback) and enter operational objectives (e.g., low-latency inference, zero-trust edge). Inspect the placement tags, model latency, and trace.
3. **Topology Contrast (30 seconds):** Compare different workload profiles (Deep Learning Core vs. Zero-Trust Edge) while holding node quotas fixed. Click **AI vs Baseline** to see how advisory placement heuristics conditioned pod density compared to a deterministic baseline.
4. **Feasibility Constraints (20 seconds):** Edit resource quotas or set a tight budget; observe how impossible allocations are blocked and negative quotas are strictly disallowed. Test the **50% Quota Shock** button to run a supply-shock counterfactual without re-querying the LLM.
5. **Consequence Verification (35 seconds):** Run the **Zombie Ack (False Success)** scenario. The control plane acknowledges `SUCCESS`, but observed node telemetry is unchanged; the independent verifier flags the discrepancy and issues a **BLOCK** verdict.
6. **Bounded Safe Recovery (20 seconds):** Grant operator authorization for safe recovery. The verifier returns **PASS** only when actual node changes match the pre-declared contract while keeping protected IAM invariants locked.
7. **Mutation Testing (25 seconds):** Run the **Mutation audit** powered by IntentProof and export the tamper-evident SHA-256 JSON audit receipt.
