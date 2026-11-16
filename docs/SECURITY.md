# Security, Integrity & Privacy: ClusterGuard

- **Server-only API keys** (`GROQ_API_KEY`, `GEMINI_API_KEY`): Never returned to clients, never stored in localStorage, and never committed to version control.
- **In-process simulation sandbox**: All cluster quotas, workload specifications, and simulated provisioning events are evaluated in-process. No live cloud provider billing or physical data centers are mutated.
- **Input hardening & rate limiting**: Same-origin POST validation, strict JSON payload size ceiling (12 KB), temporary session tokens with 1-hour TTL, per-IP rate-limiting (24 req/min), process-level live request caps, and restrictive static-file routing with strict CSP (`default-src 'self'`).
- **Independent 3-valued verification**: Command acknowledgements are explicitly untrusted; the independent verifier evaluates real telemetry and returns `PASS`, `BLOCK`, or `UNKNOWN`.
- **Pre-declared cryptographic hashing**: Contracts are hashed with canonical SHA-256 before mutation, preventing post-execution goal drift or tampering.
- **Zero-trust admission control**: Microservice workloads requiring public ingress are strictly dropped when network isolation policies are enforced.
- **Non-recoverable security side effects**: Privilege escalation breaches immediately block execution and forbid automated recovery cycles, requiring manual SRE intervention.
