# Zenux

**Zenux is an open, AI-native security engine.** It ships operator-grade
scanners for AI endpoints, RAG systems, MCP servers, and model artifacts; client
SDKs for Python and JavaScript; a Claude Code credential-leak hook; and the
ingestion contract those components speak.

> AGPL-3.0-or-later. Copyright (C) 2026 Scheduler Systems Ltd. See `LICENSE` and `NOTICE`.

## What's in this repository

| Component | Path | Description |
| --- | --- | --- |
| Scanners | `tools/01_*` … `tools/13_*` | AI-native security probes (recon, prompt injection, RAG poisoning, agent scope, MCP exploit/rug-pull, supply chain, behavioural drift, unbounded consumption, system-prompt leakage, LiteLLM policy, ML model static scan, LLMjacking). |
| Scanner library | `tools/lib/` | Canonical finding schema, target safety validation, async HTTP, Kali wrappers, LiteLLM guardrail hooks, reporter, OpenTelemetry. |
| Agent SDK | `tools/sdk/` | Background-agent client, session helper, MCP boundary wrappers, redaction. |
| Python SDK | `packages/zenux-sdk/` | `zenux` client + finding schema (publishable). |
| JS SDK | `packages/zenux-sdk-js/` | TypeScript client + types (publishable). |
| Claude Code hook | `tools/zenux_claude_hook.sh` | Blocks exposed credentials in prompts / tool I/O. Raw values never leave the machine. |
| Hook installer | `scripts/install-zenux-hooks.mjs` | Installs the hook into your Claude settings. |
| Ingestion contract | `openapi.yaml` | The OpenAPI contract scanners/SDKs/hook post to. |

The hosted multi-tenant control plane (findings triage UI, cases, assets,
policies, approvals, organization IAM, billing, and deployment automation) is a
separate, non-open product and is **not** part of this repository.

## Safety

- For **authorized testing only** — run only against systems you own or have
  explicit written permission to test.
- Target validation blocks private, loopback, and metadata targets unless
  `ALLOW_INTERNAL=1`.
- All subprocess wrappers enforce a timeout. The unbounded-consumption probe
  sends a small, fixed number of requests.
- The Claude Code hook and SDKs transmit **metadata only** — never raw
  credential values, prompts, or tool output.

## Quick start

```bash
# Scanners
cd tools
python3 -m unittest discover tests/ -v        # run the test suite

python3 run_all.py \
  --target api.example.com \
  --endpoint https://api.example.com/v1/chat/completions \
  --auth-header "Authorization: Bearer $API_KEY" \
  --output results
```

Findings are written to `results/findings.json`. To push them to a Zenux
deployment, set `ZENUX_ENDPOINT` and `INGEST_SECRET` (see `.env.example`).

### Claude Code credential-leak hook

```bash
node scripts/install-zenux-hooks.mjs           # installs into ~/.claude/settings.json
node scripts/install-zenux-hooks.mjs -- --scope project
```

## Configuration

All remote integration is optional — the scanners and hook run fully offline.
See `.env.example` for the available environment variables.

## License

This program is free software licensed under the GNU Affero General Public
License v3.0 or later. See [`LICENSE`](./LICENSE).
