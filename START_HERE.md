# Quick start: ClusterGuard

```powershell
python -m clusterguard.server
```

Open **http://127.0.0.1:8765**.

**One mission:** ClusterGuard: Deterministic Guardrail Harness for Autonomous Cloud Agents. Choose an infrastructure workload profile, synthesize a plan, inject a zombie ack fault, verify the post-state mismatch, authorize bounded recovery, run counterfactual ablations, and execute formal IntentProof mutation testing.

### Running with Live Advisory AI (Groq + Gemini Fallback)
Set your API key(s) in PowerShell or command prompt:

```powershell
$env:GROQ_API_KEY="gsk_..."     # Primary fast LLM
$env:GEMINI_API_KEY="AIza..."   # Fallback LLM
python -m clusterguard.server
```

The app works 100% offline in Sample mode with zero credentials. When configured with API keys, it uses Groq as the primary advisory optimizer and automatically falls back to Gemini if Groq encounters any issues.
