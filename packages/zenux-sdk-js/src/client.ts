/**
 * ZenuxClient — TypeScript/JavaScript SDK for ingesting findings and traces.
 *
 * Works in Node.js ≥18 and any modern browser.
 * Depends only on the built-in `fetch` API (no external dependencies).
 */

import type { FindingInput, TraceInput, ZenuxClientOptions, ZenuxResponse } from './types.js'

export class ZenuxError extends Error {
  readonly status: number
  readonly body: string

  constructor(message: string, status: number, body: string) {
    super(message)
    this.name = 'ZenuxError'
    this.status = status
    this.body = body
  }
}

export class ZenuxClient {
  private readonly baseUrl: string
  private readonly apiKey: string
  private readonly orgId: string | undefined
  private readonly timeoutMs: number
  private readonly _fetch: typeof globalThis.fetch

  /**
   * @example
   * // From env vars:
   * const client = new ZenuxClient()
   *
   * // Explicit config:
   * const client = new ZenuxClient({
   *   baseUrl: 'https://security.example.com',
   *   apiKey: process.env.ZENUX_INGEST_SECRET!,
   * })
   */
  constructor(options: ZenuxClientOptions = {}) {
    this.baseUrl = (
      options.baseUrl ??
      (typeof process !== 'undefined' ? process.env['ZENUX_ENDPOINT'] ?? '' : '')
    ).replace(/\/$/, '')

    this.apiKey =
      options.apiKey ??
      (typeof process !== 'undefined'
        ? process.env['ZENUX_INGEST_SECRET'] ?? process.env['INGEST_SECRET'] ?? ''
        : '')

    this.orgId =
      options.orgId ??
      (typeof process !== 'undefined' ? process.env['ZENUX_ORG_ID'] : undefined)

    this.timeoutMs = options.timeoutMs ?? 10_000
    this._fetch = options.fetch ?? globalThis.fetch.bind(globalThis)
  }

  /** True when baseUrl and apiKey are both present. */
  get isConfigured(): boolean {
    return this.baseUrl.length > 0 && this.apiKey.length > 0
  }

  /**
   * Ingest one or more security findings.
   *
   * Silently returns `{ ok: false }` when the client is not configured,
   * so calls are always safe to fire-and-forget.
   *
   * @throws {ZenuxError} when the API returns a non-2xx status.
   */
  async ingestFindings(findings: FindingInput[], options?: { syncToGitHub?: boolean }): Promise<ZenuxResponse> {
    if (!this.isConfigured) return { ok: false }
    if (findings.length === 0) return { ok: true }

    const payload: Record<string, unknown> = {
      findings: findings.map(this.normalizeFinding),
      syncToGitHub: options?.syncToGitHub ?? false,
    }
    if (this.orgId) payload['orgId'] = this.orgId

    return this._post('/api/ingest/findings', payload)
  }

  /**
   * Ingest a single finding (convenience wrapper).
   */
  async ingestFinding(finding: FindingInput, options?: { syncToGitHub?: boolean }): Promise<ZenuxResponse> {
    return this.ingestFindings([finding], options)
  }

  /**
   * Ingest a trace event (agent tool call, prompt/response).
   */
  async ingestTrace(trace: TraceInput): Promise<ZenuxResponse> {
    if (!this.isConfigured) return { ok: false }

    const payload: Record<string, unknown> = {
      agentId: trace.agentId,
      prompt: trace.prompt,
      response: trace.response,
      toolName: trace.toolName,
      toolInput: trace.toolInput !== undefined ? JSON.stringify(trace.toolInput).slice(0, 2000) : undefined,
      toolResult: trace.toolResult !== undefined ? String(trace.toolResult).slice(0, 2000) : undefined,
      metadata: trace.metadata,
    }
    if (this.orgId) payload['orgId'] = this.orgId

    return this._post('/api/ingest/traces', payload)
  }

  private normalizeFinding(finding: FindingInput): Record<string, unknown> {
    const result: Record<string, unknown> = {
      title: finding.title,
      severity: finding.severity ?? 'medium',
      className: finding.threatClass ?? 'other',
      source: finding.source ?? 'sdk',
      summary: finding.description ?? '',
      remediationSummary: finding.remediation ?? null,
      tags: finding.tags ?? [],
    }
    if (finding.assetId !== undefined) result['assetId'] = finding.assetId
    if (finding.externalKey !== undefined) result['externalKey'] = finding.externalKey
    return result
  }

  private async _post(path: string, body: Record<string, unknown>): Promise<ZenuxResponse> {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), this.timeoutMs)

    try {
      const response = await this._fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      })

      const text = await response.text().catch(() => '')

      if (!response.ok) {
        throw new ZenuxError(
          `Zenux API error ${response.status}: ${text.slice(0, 200)}`,
          response.status,
          text,
        )
      }

      let data: unknown
      try {
        data = JSON.parse(text)
      } catch {
        data = undefined
      }

      return { ok: true, data }
    } finally {
      clearTimeout(timer)
    }
  }
}
