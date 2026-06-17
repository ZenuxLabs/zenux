#!/usr/bin/env bash
# Zenux credential detection hook for Claude Code.
#
# Install with: pnpm zenux:hooks:install
# Default scope: ~/.claude/settings.json
# Workspace scope: pnpm zenux:hooks:install -- --scope project
# The installer writes the hook into the correct Claude settings file and
# can optionally report install status back to Zenux.
#
# Example settings.json fragment:
#   {
#     "hooks": {
#       "UserPromptSubmit": [
#         {
#           "matcher": ".*",
#           "hooks": [
#             { "type": "command", "command": "bash /path/to/tools/zenux_claude_hook.sh" }
#           ]
#         }
#       ],
#       "PreToolUse": [
#         {
#           "matcher": ".*",
#           "hooks": [
#             { "type": "command", "command": "bash /path/to/tools/zenux_claude_hook.sh" }
#           ]
#         }
#       ],
#       "PostToolUse": [
#         {
#           "matcher": ".*",
#           "hooks": [
#             { "type": "command", "command": "bash /path/to/tools/zenux_claude_hook.sh" }
#           ]
#         }
#       ]
#     }
#   }
#
# This hook scans user prompts, tool inputs, and tool output for exposed credentials and signals Zenux.
# SECURITY: Only metadata (provider label, file reference) is transmitted.
#           Raw credential values are never sent to Zenux.

set -euo pipefail

# Read the full hook payload from stdin.
INPUT=$(cat)

ZENUX_ENDPOINT="${ZENUX_ENDPOINT:-}"
INGEST_SECRET="${INGEST_SECRET:-}"

EVENT_NAME=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
data = json.load(sys.stdin)
print(data.get("hook_event_name") or data.get("hookEvent") or "")
' 2>/dev/null || echo "")

TOOL_NAME=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
data = json.load(sys.stdin)
print(data.get("tool_name") or data.get("toolName") or "")
' 2>/dev/null || echo "")

USER_PROMPT_TEXT=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
data = json.load(sys.stdin)
text = data.get("user_prompt") or data.get("userPrompt") or ""
if not isinstance(text, str):
    text = json.dumps(text, ensure_ascii=False)
print(text[:8192])
' 2>/dev/null || echo "")

TOOL_INPUT_TEXT=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
data = json.load(sys.stdin)
value = data.get("tool_input")
if value is None:
    value = data.get("toolInput")
if isinstance(value, str):
    text = value
else:
    text = json.dumps(value, ensure_ascii=False)
print(text[:4096])
' 2>/dev/null || echo "")

TOOL_RESULT_TEXT=$(printf '%s' "$INPUT" | python3 -c '
import json, sys
data = json.load(sys.stdin)
value = data.get("tool_result")
if value is None:
    value = data.get("toolResult")
if value is None:
    value = data.get("tool_response")
if value is None:
    value = data.get("toolResponse")
if isinstance(value, dict):
    text = value.get("output", "") or value.get("content", "") or json.dumps(value, ensure_ascii=False)
elif isinstance(value, str):
    text = value
else:
    text = json.dumps(value, ensure_ascii=False)
print(text[:8192])
' 2>/dev/null || echo "")

case "$EVENT_NAME" in
  UserPromptSubmit)
    SCAN_TEXT="$USER_PROMPT_TEXT"
    ;;
  PreToolUse)
    SCAN_TEXT="$TOOL_INPUT_TEXT"
    ;;
  PostToolUse)
    SCAN_TEXT="${TOOL_INPUT_TEXT} ${TOOL_RESULT_TEXT}"
    ;;
  *)
    SCAN_TEXT="${USER_PROMPT_TEXT} ${TOOL_INPUT_TEXT} ${TOOL_RESULT_TEXT}"
    ;;
esac

# Credential detection patterns (provider label : regex).
# Patterns intentionally avoid capturing full credential values in variables.
PATTERN_LABELS=(
  "Anthropic API key"
  "OpenAI project key"
  "OpenAI API key"
  "GitHub personal access token"
  "GitHub fine-grained token"
  "AWS access key"
  "Google AI key"
  "Groq key"
  "xAI key"
  "HuggingFace token"
  "Replicate token"
)

PATTERN_REGEXES=(
  "sk-ant-[A-Za-z0-9-]{20,}"
  "sk-proj-[A-Za-z0-9-]{20,}"
  "sk-[A-Za-z0-9]{20,}"
  "ghp_[A-Za-z0-9]{36}"
  "github_pat_[A-Za-z0-9_]{22,}"
  "(AKIA|ASIA)[A-Z0-9]{16}"
  "AIza[A-Za-z0-9_-]{35}"
  "gsk_[A-Za-z0-9]{20,}"
  "xai-[A-Za-z0-9]{20,}"
  "hf_[A-Za-z0-9]{20,}"
  "r8_[A-Za-z0-9]{20,}"
)

DETECTED_LABEL=""
for INDEX in "${!PATTERN_LABELS[@]}"; do
  LABEL="${PATTERN_LABELS[$INDEX]}"
  PATTERN="${PATTERN_REGEXES[$INDEX]}"
  if printf '%s' "$SCAN_TEXT" | python3 -c "
import re, sys
text = sys.stdin.read()
if re.search(r'${PATTERN}', text):
    sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
    DETECTED_LABEL="$LABEL"
    break
  fi
done

# Nothing found - exit cleanly without side effects.
if [[ -z "$DETECTED_LABEL" ]]; then
  exit 0
fi

ISO_NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SOURCE_NAME="zenux_claude_hook:${EVENT_NAME:-unknown}"
TARGET_NAME="claude-session"
SYSTEM_MESSAGE="Credential pattern matching \"${DETECTED_LABEL}\" was blocked in ${EVENT_NAME:-a Claude hook}. Review the exposure, rotate the credential, and use a secrets manager."
HOOK_JSON="{}"

if [[ "$EVENT_NAME" == "PreToolUse" ]]; then
  HOOK_JSON=$(EVENT_NAME="$EVENT_NAME" TOOL_NAME="$TOOL_NAME" DETECTED_LABEL="$DETECTED_LABEL" python3 -c '
import json
import os

event_name = os.environ.get("EVENT_NAME", "")
tool_name = os.environ.get("TOOL_NAME", "")
label = os.environ.get("DETECTED_LABEL", "")
payload = {
    "continue": False,
    "systemMessage": (
        f"Credential pattern matching \"{label}\" was blocked before tool execution"
        + (f" for tool \"{tool_name}\"." if tool_name else ".")
    ),
    "hookSpecificOutput": {
        "permissionDecision": "deny",
    },
}
print(json.dumps(payload))
')
elif [[ "$EVENT_NAME" == "PostToolUse" ]]; then
  HOOK_JSON=$(EVENT_NAME="$EVENT_NAME" TOOL_NAME="$TOOL_NAME" DETECTED_LABEL="$DETECTED_LABEL" python3 -c '
import json
import os

tool_name = os.environ.get("TOOL_NAME", "")
label = os.environ.get("DETECTED_LABEL", "")
payload = {
    "continue": False,
    "suppressOutput": True,
    "systemMessage": (
        f"Credential pattern matching \"{label}\" was blocked before tool output re-entered context"
        + (f" for tool \"{tool_name}\"." if tool_name else ".")
    ),
}
print(json.dumps(payload))
')
else
  HOOK_JSON=$(EVENT_NAME="$EVENT_NAME" TOOL_NAME="$TOOL_NAME" DETECTED_LABEL="$DETECTED_LABEL" python3 -c '
import json
import os

tool_name = os.environ.get("TOOL_NAME", "")
label = os.environ.get("DETECTED_LABEL", "")
payload = {
    "continue": False,
    "systemMessage": (
        f"Credential pattern matching \"{label}\" was blocked before the prompt reached Claude"
        + (f" for tool \"{tool_name}\"." if tool_name else ".")
    ),
}
print(json.dumps(payload))
')
fi

# Send a metadata-only finding to Zenux. Reporting is optional; the local block
# still happens even if Zenux is unavailable or misconfigured.
if [[ -n "$ZENUX_ENDPOINT" && -n "$INGEST_SECRET" ]]; then
  PAYLOAD=$(EVENT_NAME="$EVENT_NAME" TOOL_NAME="$TOOL_NAME" DETECTED_LABEL="$DETECTED_LABEL" SOURCE_NAME="$SOURCE_NAME" TARGET_NAME="$TARGET_NAME" ISO_NOW="$ISO_NOW" python3 -c '
import json
import os

event_name = os.environ.get("EVENT_NAME", "")
tool_name = os.environ.get("TOOL_NAME", "")
label = os.environ.get("DETECTED_LABEL", "")
source_name = os.environ.get("SOURCE_NAME", "")
target_name = os.environ.get("TARGET_NAME", "")
detected_at = os.environ.get("ISO_NOW", "")
event_label = event_name or "a hook event"

payload = {
    "findings": [
        {
            "title": "Exposed Credential Detected in Claude Hook",
            "className": "credential_theft",
            "severity": "critical",
            "source": source_name,
            "description": (
                f"Credential pattern matching \"{label}\" was detected during {event_label}."
                + (f" Tool \"{tool_name}\" was involved." if tool_name else "")
                + " Raw credential value was not transmitted to Zenux."
            ),
            "remediationSteps": [
                "Immediately rotate the exposed credential.",
                "Audit recent usage of the affected API key.",
                "Remove the credential from code, history, and any stored context.",
                "Use a secrets manager to store credentials instead of plain text.",
            ],
            "affectedTarget": target_name,
            "owaspCategory": "LLM02",
            "mitreAtlasTechnique": "AML.T0040 - ML Model Access",
            "riskScore": 95,
            "detectedAt": detected_at,
            "toxicity": {
                "overall": 95,
                "accessLevel": 10,
                "dataExposure": 10,
                "lateralMovement": 7,
                "exploitMaturity": 9,
                "label": "critical",
            },
        }
    ]
}
print(json.dumps(payload))
')

  curl -sf \
    -X POST \
    -H "Authorization: Bearer ${INGEST_SECRET}" \
    -H "Content-Type: application/json" \
    -d "${PAYLOAD}" \
    "${ZENUX_ENDPOINT%/}/api/ingest/findings" \
    --max-time 5 \
    > /dev/null 2>&1 &
fi

printf '%s\n' "$HOOK_JSON"
exit 0
