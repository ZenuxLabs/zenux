/** Severity levels for findings. */
export type Severity = 'low' | 'medium' | 'high' | 'critical'

/** Threat class taxonomy. */
export type ThreatClass =
  | 'prompt_injection'
  | 'indirect_injection'
  | 'jailbreak'
  | 'data_exfiltration'
  | 'tool_misuse'
  | 'mcp_abuse'
  | 'credential_theft'
  | 'model_poisoning'
  | 'intent_escalation'
  | 'supply_chain'
  | 'other'

/** A security finding to report to Zenux. */
export interface FindingInput {
  /** Short description of the finding (required). */
  title: string
  /** Severity level (default: "medium"). */
  severity?: Severity
  /** Threat class from the taxonomy (default: "other"). */
  threatClass?: ThreatClass
  /** Identifier of the affected asset, agent, or service. */
  assetId?: string
  /** Detailed description of the issue. */
  description?: string
  /** Suggested remediation steps. */
  remediation?: string
  /** Arbitrary string tags. */
  tags?: string[]
  /** Originating scanner or system (default: "sdk"). */
  source?: string
  /** Idempotency key — re-submitting the same key deduplicates. */
  externalKey?: string
}

/** A trace event for an agent tool call. */
export interface TraceInput {
  /** Identifier of the agent producing the trace. */
  agentId: string
  /** The prompt or instruction sent to the model. */
  prompt?: string
  /** The model's response. */
  response?: string
  /** Tool name if this is a tool call trace. */
  toolName?: string
  /** Tool input (will be truncated/redacted before transmission). */
  toolInput?: unknown
  /** Tool result (will be truncated/redacted before transmission). */
  toolResult?: unknown
  /** Arbitrary metadata. */
  metadata?: Record<string, string | number | boolean | null>
}

/** Configuration options for ZenuxClient. */
export interface ZenuxClientOptions {
  /** Base URL of your Zenux deployment. Defaults to ZENUX_ENDPOINT env var. */
  baseUrl?: string
  /** Ingest bearer token. Defaults to ZENUX_INGEST_SECRET env var. */
  apiKey?: string
  /** Organisation identifier. Defaults to ZENUX_ORG_ID env var. */
  orgId?: string
  /** Request timeout in milliseconds (default: 10 000). */
  timeoutMs?: number
  /** Custom fetch implementation (useful for testing). */
  fetch?: typeof globalThis.fetch
}

export interface ZenuxResponse {
  ok: boolean
  data?: unknown
}
