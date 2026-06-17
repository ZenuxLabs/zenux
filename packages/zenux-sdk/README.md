# zenux-sdk (Python)

Python SDK for ingesting security findings and traces into [Zenux](https://github.com/ZenuxLabs/zenux),
an open, AI-native security engine.

The client transmits **metadata only** — never raw credential values, prompts, or
tool output. Calls are safe to fire-and-forget: when the client is not configured
(endpoint or secret missing) `ingest()` returns an empty dict instead of raising.

## Install

```bash
pip install zenux-sdk
```

Requires Python >= 3.10. The only runtime dependency is `requests`.

## Configuration

The client reads configuration from constructor arguments or environment variables:

| Setting | Constructor arg | Environment variable |
| --- | --- | --- |
| Base URL of your Zenux deployment | `endpoint` | `ZENUX_ENDPOINT` |
| Ingest bearer token | `secret` | `ZENUX_INGEST_SECRET` (or `INGEST_SECRET`) |
| Organisation identifier | `org_id` | `ZENUX_ORG_ID` |

Do not hardcode the ingest secret — read it from the environment or a secret store.

## Usage

```python
from zenux import ZenuxClient, Finding

client = ZenuxClient()  # reads ZENUX_ENDPOINT / ZENUX_INGEST_SECRET from env

client.ingest(Finding(
    title="Prompt injection in summarise_email tool",
    severity="high",
    threat_class="prompt_injection",
    asset_id="email-agent-prod",
    description="User-supplied email body overrode the system instruction.",
    remediation="Wrap untrusted content in a delimiter and re-assert the system prompt.",
))
```

Report several findings at once, or pass an existing list:

```python
client.ingest(finding_a, finding_b, sync_to_github=True)
client.ingest_batch([finding_a, finding_b])
```

`ingest()` raises `ZenuxError` if the API returns a non-2xx status.

## Finding schema

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `title` | `str` | — | Required. Short description of the finding. |
| `severity` | `"low" \| "medium" \| "high" \| "critical"` | `"medium"` | |
| `threat_class` | `ThreatClass` literal | `"other"` | e.g. `prompt_injection`, `mcp_abuse`, `supply_chain`. |
| `asset_id` | `str \| None` | `None` | Affected asset, agent, or service. |
| `description` | `str` | `""` | Detailed explanation. |
| `remediation` | `str` | `""` | Suggested remediation steps. |
| `tags` | `list[str]` | `[]` | Arbitrary string labels. |
| `source` | `str` | `"sdk"` | Originating scanner or system. |
| `external_key` | `str \| None` | `None` | Idempotency key — re-submitting the same key deduplicates. |

## License

MIT. See the repository `LICENSE` and `NOTICE` for full terms.
