# @zenux/sdk (TypeScript / JavaScript)

TypeScript/JavaScript SDK for ingesting security findings and traces into
[Zenux](https://github.com/ZenuxLabs/zenux), an open, AI-native security engine.

Works in Node.js >= 18 and any modern browser. Depends only on the built-in
`fetch` API — no external runtime dependencies. The client transmits **metadata
only** — never raw credential values, prompts, or tool output. Calls are safe to
fire-and-forget: when the client is not configured (base URL or API key missing),
methods return `{ ok: false }` instead of throwing.

## Install

```bash
npm install @zenux/sdk
```

The package ships both ESM and CommonJS builds plus type declarations:

```ts
import { ZenuxClient } from '@zenux/sdk'        // ESM
```

```js
const { ZenuxClient } = require('@zenux/sdk')   // CommonJS
```

## Configuration

The client reads configuration from constructor options or environment variables:

| Setting | Option | Environment variable |
| --- | --- | --- |
| Base URL of your Zenux deployment | `baseUrl` | `ZENUX_ENDPOINT` |
| Ingest bearer token | `apiKey` | `ZENUX_INGEST_SECRET` (or `INGEST_SECRET`) |
| Organisation identifier | `orgId` | `ZENUX_ORG_ID` |
| Request timeout (ms) | `timeoutMs` | — (default `10000`) |

Do not hardcode the API key — read it from the environment or a secret store.

## Usage

```ts
import { ZenuxClient } from '@zenux/sdk'

const client = new ZenuxClient() // reads ZENUX_ENDPOINT / ZENUX_INGEST_SECRET from env

await client.ingestFinding({
  title: 'Prompt injection in summarise_email tool',
  severity: 'high',
  threatClass: 'prompt_injection',
  assetId: 'email-agent-prod',
  description: 'User-supplied email body overrode the system instruction.',
  remediation: 'Wrap untrusted content in a delimiter and re-assert the system prompt.',
})

// Several at once, with optional GitHub sync:
await client.ingestFindings([findingA, findingB], { syncToGitHub: true })

// Trace an agent tool call:
await client.ingestTrace({
  agentId: 'email-agent-prod',
  toolName: 'summarise_email',
  toolInput: { messageId: 'abc' },
})
```

Every method returns `Promise<ZenuxResponse>` (`{ ok: boolean; data?: unknown }`)
and throws `ZenuxError` (with `.status` and `.body`) on a non-2xx API response.

## Finding input

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `title` | `string` | — | Required. Short description of the finding. |
| `severity` | `'low' \| 'medium' \| 'high' \| 'critical'` | `'medium'` | |
| `threatClass` | `ThreatClass` | `'other'` | e.g. `prompt_injection`, `mcp_abuse`, `supply_chain`. |
| `assetId` | `string` | — | Affected asset, agent, or service. |
| `description` | `string` | `''` | Detailed explanation. |
| `remediation` | `string` | — | Suggested remediation steps. |
| `tags` | `string[]` | `[]` | Arbitrary string labels. |
| `source` | `string` | `'sdk'` | Originating scanner or system. |
| `externalKey` | `string` | — | Idempotency key — re-submitting the same key deduplicates. |

## Build

```bash
npm install
npm run build      # emits dist/esm, dist/cjs, and dist/types
npm run typecheck  # type-check only, no emit
```

## License

**Apache-2.0.** See the [`LICENSE`](./LICENSE) file in this package directory.

Zenux is dual-licensed under a standard open-core model:

- **This client SDK** (`@zenux/sdk`) is licensed under **Apache-2.0** so that any
  external developer can freely import and integrate it — including in
  closed-source and commercial applications — without the copyleft obligations of
  the AGPL. A permissive SDK is what lets the ecosystem actually adopt Zenux.
- **The Zenux server / security engine** (the scanners, scanner library, agent
  SDK, and ingestion services in the repository root) remains licensed under
  **AGPL-3.0-or-later**. See the repository root [`LICENSE`](../../LICENSE) and
  [`NOTICE`](../../NOTICE).

Using this SDK to talk to a Zenux deployment does not place your application
under the AGPL.
