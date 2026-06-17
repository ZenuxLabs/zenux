# Zenux Scan Toolkit

Eight AI-native security scanners for operator-grade assessment of AI endpoints, RAG systems, MCP servers, and model artifact surfaces.

Safety:
- For authorized testing only.
- Default target validation blocks private, loopback, and metadata targets unless `ALLOW_INTERNAL=1`.
- All subprocess wrappers enforce `timeout=60`.
- The unbounded-consumption concurrency probe sends exactly 5 requests.

Layout:
- `lib/schema.py`: canonical finding schema and toxicity breakdown
- `lib/target.py`: target safety validation
- `lib/kali.py`: `nmap`, `gobuster`, `nikto`, and `httpx` wrappers
- `lib/http.py`: async HTTP helpers
- `lib/litellm_hooks.py`: LiteLLM guardrail hook templates for prompt injection, credential leakage, and trace reporting
- `lib/reporter.py`: finding -> GitHub Issue reporter
- `sdk/`: Zenux background-agent SDK, session helpers, and MCP boundary wrappers
- `01_*` to `08_*`: exclusive AI security tools
- `run_all.py`: orchestrator and summary output

Run tests:

```bash
cd apps/security-command-center/tools
python3 -m unittest discover tests/ -v
```

Run all tools:

```bash
python3 run_all.py \
  --target api.example.com \
  --endpoint https://api.example.com/v1/chat/completions \
  --auth-header "Authorization: Bearer $API_KEY" \
  --output results
```

Output:
- `results/findings.json`
- summary table grouped by severity and score
- optional GitHub Issue creation when `--push-github --github-token ...` is provided
- Zenux session/audit telemetry when `ZENUX_ENDPOINT` and an ingest secret are configured
