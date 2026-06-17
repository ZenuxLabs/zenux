#!/usr/bin/env node
/**
 * Zenux Claude hook installer.
 *
 * Installs the Claude Code credential-enforcement hook into the user-level or
 * workspace-level Claude settings file. The installer is intentionally
 * conservative:
 * - it only touches the requested settings file
 * - it preserves unrelated settings
 * - it refuses to silently rewrite invalid JSON
 * - reporting back to Zenux is optional and non-blocking
 */

import fs from 'node:fs/promises'
import { existsSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url))
const DEFAULT_REPO_ROOT = path.resolve(MODULE_DIR, '..')
const HOOK_PHASES = ['UserPromptSubmit', 'PreToolUse', 'PostToolUse']
const HOOK_MATCHER = '.*'

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function cloneJson(value) {
  return value == null ? {} : JSON.parse(JSON.stringify(value))
}

function shellQuote(value) {
  if (value.length === 0) {
    return "''"
  }

  return `'${value.replace(/'/g, `'"'"'`)}'`
}

function asNormalizedCommand(command) {
  return command.trim().replace(/\s+/g, ' ')
}

function buildHookScriptPath(repoRoot) {
  return path.resolve(repoRoot, 'tools', 'zenux_claude_hook.sh')
}

export function buildHookCommand(
  repoRoot = DEFAULT_REPO_ROOT,
  { validateScriptExists = true, zenuxEndpoint = '', ingestSecret = '' } = {},
) {
  const hookScriptPath = buildHookScriptPath(repoRoot)
  if (validateScriptExists && !existsSync(hookScriptPath)) {
    throw new Error(`Claude hook script not found at ${hookScriptPath}`)
  }

  const envPrefix =
    zenuxEndpoint && ingestSecret
      ? `ZENUX_ENDPOINT=${shellQuote(zenuxEndpoint)} INGEST_SECRET=${shellQuote(ingestSecret)} `
      : ''

  return `${envPrefix}bash ${shellQuote(hookScriptPath)}`
}

export function resolveSettingsPath({
  scope = 'user',
  settingsPath,
  repoRoot = DEFAULT_REPO_ROOT,
  homeDir = os.homedir(),
} = {}) {
  if (settingsPath) {
    return path.resolve(settingsPath)
  }

  if (scope === 'project') {
    return path.join(path.resolve(repoRoot), '.claude', 'settings.json')
  }

  return path.join(path.resolve(homeDir), '.claude', 'settings.json')
}

function normalizeSettingsRoot(existing) {
  if (!isPlainObject(existing)) {
    return {}
  }

  return cloneJson(existing)
}

function ensureHookCollection(config) {
  const next = normalizeSettingsRoot(config)
  if (next.hooks === undefined) {
    next.hooks = {}
  } else if (!isPlainObject(next.hooks)) {
    throw new Error('Claude settings file has an unsupported hooks shape.')
  }

  return next
}

function isZenuxCommandHook(entry, command) {
  return (
    isPlainObject(entry) &&
    entry.type === 'command' &&
    asNormalizedCommand(String(entry.command ?? '')) === asNormalizedCommand(command)
  )
}

function cloneHookEntry(entry) {
  if (!isPlainObject(entry)) {
    return entry
  }

  const next = cloneJson(entry)
  if (Array.isArray(next.hooks)) {
    next.hooks = next.hooks.map((hook) => cloneJson(hook))
  }

  return next
}

function normalizeHookSection(section) {
  if (!Array.isArray(section)) {
    return []
  }

  return section.map((entry) => cloneHookEntry(entry))
}

export function buildClaudeHookEntry(command) {
  return {
    matcher: HOOK_MATCHER,
    hooks: [
      {
        type: 'command',
        command,
      },
    ],
  }
}

export function addZenuxClaudeHook(existingSettings, command) {
  const config = ensureHookCollection(existingSettings)
  const hooks = config.hooks
  let changed = false

  for (const phase of HOOK_PHASES) {
    if (hooks[phase] !== undefined && !Array.isArray(hooks[phase])) {
      throw new Error(`Claude settings file has an unsupported ${phase} shape.`)
    }

    const entries = normalizeHookSection(hooks[phase])
    if (entries.some((entry) => Array.isArray(entry.hooks) && entry.hooks.some((hook) => isZenuxCommandHook(hook, command)))) {
      continue
    }

    entries.push(buildClaudeHookEntry(command))
    hooks[phase] = entries
    changed = true
  }

  return { config, changed }
}

export function removeZenuxClaudeHook(existingSettings, command) {
  const config = ensureHookCollection(existingSettings)
  const hooks = config.hooks
  let changed = false

  for (const phase of HOOK_PHASES) {
    if (hooks[phase] !== undefined && !Array.isArray(hooks[phase])) {
      throw new Error(`Claude settings file has an unsupported ${phase} shape.`)
    }

    const phaseEntries = normalizeHookSection(hooks[phase])
    const nextEntries = phaseEntries
      .map((entry) => {
        if (!isPlainObject(entry) || !Array.isArray(entry.hooks)) {
          return entry
        }

        const nextHooks = entry.hooks.filter((hook) => !isZenuxCommandHook(hook, command))
        if (nextHooks.length !== entry.hooks.length) {
          changed = true
        }

        if (nextHooks.length === 0) {
          return null
        }

        return {
          ...entry,
          hooks: nextHooks,
        }
      })
      .filter((entry) => entry !== null)

    if (nextEntries.length !== phaseEntries.length) {
      changed = true
    }

    if (nextEntries.length > 0) {
      hooks[phase] = nextEntries
    } else {
      delete hooks[phase]
    }
  }

  if (Object.keys(hooks).length === 0) {
    delete config.hooks
  }

  return { config, changed }
}

async function readSettingsFile(settingsPath) {
  try {
    const raw = await fs.readFile(settingsPath, 'utf8')
    if (!raw.trim()) {
      return {}
    }

    return JSON.parse(raw)
  } catch (error) {
    if (error && typeof error === 'object' && error.code === 'ENOENT') {
      return {}
    }

    if (error instanceof SyntaxError) {
      throw new Error(`Claude settings file at ${settingsPath} is not valid JSON.`)
    }

    throw error
  }
}

async function writeSettingsFile(settingsPath, config) {
  await fs.mkdir(path.dirname(settingsPath), { recursive: true })
  const serialized = `${JSON.stringify(config, null, 2)}\n`
  const tempPath = `${settingsPath}.${process.pid}.zenux.tmp`

  try {
    await fs.writeFile(tempPath, serialized, 'utf8')
    await fs.rename(tempPath, settingsPath)
  } finally {
    await fs.unlink(tempPath).catch(() => {})
  }
}

function getReportingCredentials() {
  const endpoint = (process.env.ZENUX_ENDPOINT ?? '').trim()
  const token =
    (process.env.ZENUX_SERVICE_TOKEN ?? '').trim() ||
    (process.env.CONTROL_PLANE_SERVICE_TOKEN ?? '').trim() ||
    (process.env.CONTROL_PLANE_ADMIN_TOKEN ?? '').trim()

  return { endpoint, token }
}

async function reportInstallStatus({ action, scope }) {
  const { endpoint, token } = getReportingCredentials()
  if (!endpoint || !token) {
    return { status: 'skipped', reason: 'missing ZENUX_ENDPOINT or service token' }
  }

  const titleByAction = {
    install: 'Zenux Claude hook installed',
    repair: 'Zenux Claude hook repaired',
    uninstall: 'Zenux Claude hook removed',
  }

  const bodyByAction = {
    install: `Claude Code hook is active in ${scope} scope.`,
    repair: `Claude Code hook was verified in ${scope} scope.`,
    uninstall: `Claude Code hook was removed from ${scope} scope.`,
  }

  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 5000)

  try {
    const response = await fetch(`${endpoint.replace(/\/+$/, '')}/api/notifications`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      signal: controller.signal,
      body: JSON.stringify({
        title: titleByAction[action],
        body: bodyByAction[action],
        targetRef: 'claude-code-hook',
        requestedBy: process.env.USER ?? process.env.USERNAME ?? 'zenux-hook-installer',
        metadata: {
          surface: 'claude-code',
          scope,
          action,
        },
      }),
    })

    if (!response.ok) {
      const text = await response.text().catch(() => '')
      return {
        status: 'failed',
        reason: `notifications endpoint returned ${response.status}${text ? `: ${text}` : ''}`,
      }
    }

    return { status: 'sent' }
  } catch (error) {
    return {
      status: 'failed',
      reason:
        error instanceof Error && error.name === 'AbortError'
          ? 'status report timed out after 5 seconds'
          : error instanceof Error
            ? error.message
            : 'status report failed',
    }
  } finally {
    clearTimeout(timeout)
  }
}

function parseArgs(argv) {
  const options = {
    action: 'install',
    scope: 'user',
    dryRun: false,
    report: true,
    repoRoot: DEFAULT_REPO_ROOT,
    settingsPath: null,
  }

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]

    if (arg === '--help' || arg === '-h') {
      options.help = true
      continue
    }

    if (arg === '--dry-run') {
      options.dryRun = true
      continue
    }

    if (arg === '--no-report') {
      options.report = false
      continue
    }

    if (arg === '--report') {
      options.report = true
      continue
    }

    if (arg === '--repair') {
      options.action = 'repair'
      continue
    }

    if (arg === '--uninstall') {
      options.action = 'uninstall'
      continue
    }

    if (arg === '--scope') {
      const scope = argv[++index]
      if (scope !== 'user' && scope !== 'project') {
        throw new Error('--scope must be either user or project')
      }

      options.scope = scope
      continue
    }

    if (arg === '--project-root') {
      const repoRoot = argv[++index]
      if (!repoRoot) {
        throw new Error('--project-root requires a path')
      }

      options.repoRoot = path.resolve(repoRoot)
      continue
    }

    if (arg === '--settings-path') {
      const settingsPath = argv[++index]
      if (!settingsPath) {
        throw new Error('--settings-path requires a path')
      }

      options.settingsPath = path.resolve(settingsPath)
      continue
    }

    throw new Error(`Unknown argument: ${arg}`)
  }

  return options
}

function printUsage() {
  process.stdout.write(
    [
      'Usage: node scripts/install-zenux-hooks.mjs [options]',
      '',
      'Options:',
      '  --scope user|project     Target ~/.claude/settings.json or <repo>/.claude/settings.json',
      '  --settings-path PATH     Override the Claude settings path explicitly',
      '  --project-root PATH      Override the repo root used to locate tools/zenux_claude_hook.sh',
      '  --repair                 Re-apply the hook without changing unrelated settings',
      '  --uninstall              Remove the Zenux hook from the chosen settings file',
      '  --dry-run                Show what would change without writing anything',
      '  --no-report              Skip the optional Zenux status notification',
      '  --report                 Force status notification back on',
      '  -h, --help               Show this help text',
      '',
      'The default scope is user, which writes to ~/.claude/settings.json.',
    ].join('\n') + '\n',
  )
}

export async function runInstaller({
  action = 'install',
  scope = 'user',
  dryRun = false,
  report = true,
  repoRoot = DEFAULT_REPO_ROOT,
  settingsPath = null,
} = {}) {
  const resolvedSettingsPath = resolveSettingsPath({
    scope,
    settingsPath,
    repoRoot,
  })

  const zenuxEndpoint = (process.env.ZENUX_ENDPOINT ?? '').trim()
  const ingestSecret =
    (process.env.INGEST_SECRET ?? '').trim() ||
    (process.env.ZENUX_SERVICE_TOKEN ?? '').trim() ||
    (process.env.CONTROL_PLANE_SERVICE_TOKEN ?? '').trim()

  const hookCommand = buildHookCommand(repoRoot, {
    validateScriptExists: action !== 'uninstall',
    zenuxEndpoint,
    ingestSecret,
  })
  const currentSettings = await readSettingsFile(resolvedSettingsPath)
  const result =
    action === 'uninstall'
      ? removeZenuxClaudeHook(currentSettings, hookCommand)
      : addZenuxClaudeHook(currentSettings, hookCommand)

  if (result.changed && !dryRun) {
    await writeSettingsFile(resolvedSettingsPath, result.config)
  } else if (!result.changed && !existsSync(resolvedSettingsPath) && !dryRun && action !== 'uninstall') {
    // A fresh install should create the file even if it was previously absent.
    await writeSettingsFile(resolvedSettingsPath, result.config)
  }

  const reportResult = dryRun
    ? { status: 'skipped', reason: 'dry run' }
    : report
      ? await reportInstallStatus({ action, scope })
      : { status: 'skipped', reason: 'disabled' }

  return {
    action,
    changed: result.changed,
    dryRun,
    scope,
    settingsPath: resolvedSettingsPath,
    reportResult,
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) {
    printUsage()
    return
  }

  const result = await runInstaller(args)

  const messageByAction = {
    install: result.changed
      ? `Installed Zenux Claude hook at ${result.settingsPath}`
      : `Zenux Claude hook is already installed in ${result.settingsPath}`,
    repair: result.changed
      ? `Repaired Zenux Claude hook at ${result.settingsPath}`
      : `Zenux Claude hook was already healthy in ${result.settingsPath}`,
    uninstall: result.changed
      ? `Removed Zenux Claude hook from ${result.settingsPath}`
      : `Zenux Claude hook was not present in ${result.settingsPath}`,
  }

  process.stdout.write(`${messageByAction[result.action]}${result.dryRun ? ' (dry run)' : ''}\n`)

  if (result.reportResult.status === 'sent') {
    process.stdout.write('Reported status back to Zenux.\n')
  } else if (result.reportResult.status === 'failed') {
    process.stdout.write(`Status report failed: ${result.reportResult.reason}\n`)
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
    process.exitCode = 1
  })
}
