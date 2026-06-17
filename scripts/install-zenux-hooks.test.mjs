import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { describe, expect, it } from 'vitest'

import {
  addZenuxClaudeHook,
  buildHookCommand,
  removeZenuxClaudeHook,
  resolveSettingsPath,
  runInstaller,
} from './install-zenux-hooks.mjs'

const TEST_DIR = mkdtempSync(path.join(os.tmpdir(), 'zenux-hook-installer-'))
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'))
}

describe('zenux claude hook installer', () => {
  it('builds a quoted command for the repo-local hook script', () => {
    const command = buildHookCommand(REPO_ROOT)

    expect(command.startsWith('bash ')).toBe(true)
    expect(command).toContain('/tools/zenux_claude_hook.sh')
  })

  it('resolves the expected user and project settings paths', () => {
    expect(
      resolveSettingsPath({
        scope: 'user',
        homeDir: '/home/example',
        repoRoot: '/repo',
      }),
    ).toBe('/home/example/.claude/settings.json')

    expect(
      resolveSettingsPath({
        scope: 'project',
        homeDir: '/home/example',
        repoRoot: '/repo',
      }),
    ).toBe('/repo/.claude/settings.json')

    expect(
      resolveSettingsPath({
        settingsPath: '/tmp/custom-settings.json',
        scope: 'project',
        homeDir: '/home/example',
        repoRoot: '/repo',
      }),
    ).toBe('/tmp/custom-settings.json')
  })

  it('installs, deduplicates, and uninstalls the Claude hook without disturbing other hooks', async () => {
    const settingsPath = path.join(TEST_DIR, 'settings.json')
    const initialSettings = {
      ui: {
        theme: 'midnight',
      },
      hooks: {
        PreToolUse: [
          {
            matcher: '.*',
            hooks: [
              {
                type: 'command',
                command: 'echo pre-tool',
              },
            ],
          },
        ],
        PostToolUse: [
          {
            matcher: '^copy$',
            hooks: [
              {
                type: 'command',
                command: 'echo post-tool',
              },
            ],
          },
        ],
      },
    }

    writeFileSync(settingsPath, `${JSON.stringify(initialSettings, null, 2)}\n`)

    const installResult = await runInstaller({
      settingsPath,
      repoRoot: REPO_ROOT,
      report: false,
    })

    expect(installResult.changed).toBe(true)

    const installed = readJson(settingsPath)
    expect(installed.ui.theme).toBe('midnight')
    expect(installed.hooks.UserPromptSubmit).toHaveLength(1)
    expect(installed.hooks.PreToolUse).toHaveLength(2)
    expect(installed.hooks.PostToolUse).toHaveLength(2)
    expect(installed.hooks.UserPromptSubmit[0].matcher).toBe('.*')
    expect(installed.hooks.UserPromptSubmit[0].hooks[0].type).toBe('command')
    expect(installed.hooks.UserPromptSubmit[0].hooks[0].command).toContain('tools/zenux_claude_hook.sh')
    expect(installed.hooks.PreToolUse[1].matcher).toBe('.*')
    expect(installed.hooks.PreToolUse[1].hooks[0].type).toBe('command')
    expect(installed.hooks.PreToolUse[1].hooks[0].command).toContain('tools/zenux_claude_hook.sh')
    expect(installed.hooks.PostToolUse[1].matcher).toBe('.*')
    expect(installed.hooks.PostToolUse[1].hooks[0].type).toBe('command')
    expect(installed.hooks.PostToolUse[1].hooks[0].command).toContain('tools/zenux_claude_hook.sh')

    const secondInstall = await runInstaller({
      settingsPath,
      repoRoot: REPO_ROOT,
      report: false,
    })

    expect(secondInstall.changed).toBe(false)

    const reinstall = readJson(settingsPath)
    expect(reinstall.hooks.UserPromptSubmit).toHaveLength(1)
    expect(reinstall.hooks.PreToolUse).toHaveLength(2)
    expect(reinstall.hooks.PostToolUse).toHaveLength(2)

    const uninstallResult = await runInstaller({
      action: 'uninstall',
      settingsPath,
      repoRoot: REPO_ROOT,
      report: false,
    })

    expect(uninstallResult.changed).toBe(true)

    const uninstalled = readJson(settingsPath)
    expect(uninstalled.ui.theme).toBe('midnight')
    expect(uninstalled.hooks.UserPromptSubmit).toBeUndefined()
    expect(uninstalled.hooks.PreToolUse).toHaveLength(1)
    expect(uninstalled.hooks.PostToolUse).toHaveLength(1)
    expect(uninstalled.hooks.PostToolUse[0].hooks[0].command).toBe('echo post-tool')
  })

  it('can add and remove the hook from an empty settings object', () => {
    const command = buildHookCommand(REPO_ROOT)

    const installed = addZenuxClaudeHook({}, command)
    expect(installed.changed).toBe(true)
    expect(installed.config.hooks.UserPromptSubmit).toHaveLength(1)
    expect(installed.config.hooks.PreToolUse).toHaveLength(1)
    expect(installed.config.hooks.PostToolUse).toHaveLength(1)

    const removed = removeZenuxClaudeHook(installed.config, command)
    expect(removed.changed).toBe(true)
    expect(removed.config.hooks).toBeUndefined()
  })

  it('supports a dry run without writing to disk', async () => {
    const settingsPath = path.join(TEST_DIR, 'dry-run-settings.json')
    const before = {
      hooks: {
        PostToolUse: [
          {
            matcher: '^copy$',
            hooks: [
              {
                type: 'command',
                command: 'echo post-tool',
              },
            ],
          },
        ],
      },
    }

    writeFileSync(settingsPath, `${JSON.stringify(before, null, 2)}\n`)
    const original = readFileSync(settingsPath, 'utf8')

    const result = await runInstaller({
      settingsPath,
      repoRoot: REPO_ROOT,
      dryRun: true,
      report: true,
    })

    expect(result.dryRun).toBe(true)
    expect(result.changed).toBe(true)
    expect(result.reportResult.status).toBe('skipped')
    expect(result.reportResult.reason).toBe('dry run')
    expect(readFileSync(settingsPath, 'utf8')).toBe(original)
  })

  it('refuses to rewrite unsupported hook shapes', () => {
    const command = buildHookCommand(REPO_ROOT)

    expect(() =>
      addZenuxClaudeHook(
        {
          hooks: {
            PostToolUse: {
              matcher: '.*',
            },
          },
        },
        command,
      ),
    ).toThrow(/unsupported PostToolUse shape/i)

    expect(() =>
      removeZenuxClaudeHook(
        {
          hooks: {
            PostToolUse: {
              matcher: '.*',
            },
          },
        },
        command,
      ),
    ).toThrow(/unsupported PostToolUse shape/i)
  })
})
