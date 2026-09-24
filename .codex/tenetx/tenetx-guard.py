#!/usr/bin/env python3
"""TenetX VMCP Hook for OpenAI Codex (CLI + Mac App).

This script is called by Codex's hook events (PreToolUse, PermissionRequest,
PostToolUse, UserPromptSubmit, SessionStart, SessionEnd, Stop,
SubagentStart, SubagentStop, PreCompact, PostCompact) to enforce security
policies and capture observe-only lifecycle.

Current Codex runtime notes:
- Current Codex runtimes emit Bash, apply_patch/Edit/Write, and native
  mcp__server__tool events. Browser controls remain adapter-backed.
- PreToolUse cannot present a hook-owned approval dialog. TenetX ASK
  decisions defer only when the server expects Codex's native permission
  prompt and the managed TenetX Codex prompt rules are installed.
- PostToolUse output replacement is not enforced by all Codex runtimes, so
  modified output is withheld by blocking continuation.

SECURITY MODEL: Tenant-Controlled Fail Posture
-----------------------------------------------
- Valid server policy verdicts are authoritative (except guard integrity).
- On API failure or invalid verdict, high-risk actions always fail CLOSED.
- Default product posture allows lower-risk actions during an outage.
- Strict tenants can set TENETX_FAIL_MODE=closed to block on API errors.
- TENETX_FAIL_MODE=tiered additionally honors LOCAL_FAILSAFE for writes.

Exit codes:
- 0: Allow the hook event to continue
- 2: Block the tool call (alternative to JSON block)

Environment variables:
- TENETX_URL: TenetX API URL (required)
- TENETX_ORG: Organization slug (required)
- TENETX_USER_EMAIL: User's corporate email for compliance tracking
- TENETX_TIMEOUT: API timeout in seconds (default: 5)
- TENETX_FAIL_MODE: "open" (default), "tiered", or "closed"
- TENETX_CODEX_PERMISSION_ASK_MODE: "deny" (default) or "defer"
- TENETX_CODEX_NATIVE_PROMPT: optional force switch ("true" or "false")
- TENETX_VMCP_TOKEN: Bearer token for API auth
- TENETX_VMCP_TOKEN_FILE: File containing bearer token
- TENETX_VMCP_DEBUG: Enable debug logging ("1", "true", "yes")
  Minimal non-sensitive approval RCA telemetry is always written to
  ~/.tenetx/logs/vmcp_codex.log for ASK feedback delivery.

Install:
1. Save to ~/.tenetx/hooks/codex/tenetx-guard.py
2. Add hooks to ~/.codex/hooks.json
3. Set [features] hooks = true in ~/.codex/config.toml

Reference: https://developers.openai.com/codex/hooks
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import shlex
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import urlparse

TENETX_URL = os.environ.get("TENETX_URL", "https://sanketlocal.local.tenetx.ai").rstrip("/")
TENETX_ORG = os.environ.get("TENETX_ORG", "sanketlocal")
TIMEOUT = int(os.environ.get("TENETX_TIMEOUT", "5"))

_RESPONSE_HOOK_STARTED = time.monotonic()
_RESPONSE_HTTP_BUDGET = 5.0
for _response_arg in sys.argv[1:]:
    if _response_arg.startswith("--tenetx-response-timeout-seconds="):
        import math
        try:
            _response_value = float(_response_arg.split("=", 1)[1])
            if not math.isfinite(_response_value) or _response_value < 1:
                raise ValueError("invalid response timeout")
            _RESPONSE_HTTP_BUDGET = min(_response_value, 75.0)
        except ValueError:
            print("CAPTURE_HEALTH response_budget_invalid", file=sys.stderr)
        sys.argv.remove(_response_arg)


def _response_http_timeout():
    # Multiple response checks in one event share the process budget. Raise
    # through the adapter's existing outage path when no time remains.
    remaining = _RESPONSE_HTTP_BUDGET - (time.monotonic() - _RESPONSE_HOOK_STARTED)
    if remaining <= 0:
        raise TimeoutError("response budget exhausted")
    return remaining

CODEX_BROWSER_ADAPTER_VERSION = "1.3.3"
CODEX_BROWSER_ADAPTER_SHA256 = "d38133db6941373e7a7c43a3a107c8c1469a56e3ec93cc39e8cf83c135275b8f"
CODEX_BROWSER_SKILL_SHA256 = "c224e1e7814796d8ecf86c70a94d7de1a5f035ffdea2068e10424a6a75c09111"

def _codex_browser_bundle_hook_home():
    script_path = Path(__file__).resolve()
    script_dir = script_path.parent
    if script_dir.name == "current":
        return script_dir.parent
    if script_dir.parent.name == "versions":
        return script_dir.parent.parent
    return script_dir


def _codex_browser_bundle_file_sha256(path):
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return ""


def _codex_browser_bundle_url_is_trusted(url):
    try:
        base = urlparse(TENETX_URL)
        candidate = urlparse(str(url or ""))
    except Exception:
        return False
    return bool(
        candidate.scheme
        and candidate.hostname
        and candidate.scheme == base.scheme
        and (candidate.hostname or "").lower() == (base.hostname or "").lower()
        and candidate.port == base.port
    )


def _codex_browser_bundle_get(url):
    headers = {"User-Agent": USER_AGENT}
    if VMCP_TOKEN:
        headers["Authorization"] = "Bearer " + VMCP_TOKEN
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(
        request,
        timeout=TIMEOUT,
        context=SSL_CONTEXT,
    ) as response:
        return response.read().decode("utf-8")


def _codex_browser_bundle_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_path = tempfile.mkstemp(
        prefix=".tenetx-browser-",
        suffix=path.suffix or ".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except OSError:
                pass


def _maybe_refresh_codex_browser_bundle():
    expected_adapter = str(CODEX_BROWSER_ADAPTER_SHA256 or "")
    expected_skill = str(CODEX_BROWSER_SKILL_SHA256 or "")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_adapter):
        raise ValueError("browser_adapter_manifest_invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_skill):
        raise ValueError("browser_skill_manifest_invalid")

    hook_home = _codex_browser_bundle_hook_home()
    adapter_path = hook_home / "tenetx-browser-guard.mjs"
    skill_path = (
        Path.home()
        / ".agents"
        / "skills"
        / "tenetx-browser"
        / "SKILL.md"
    )
    if (
        _codex_browser_bundle_file_sha256(adapter_path) == expected_adapter
        and _codex_browser_bundle_file_sha256(skill_path) == expected_skill
    ):
        return False

    adapter_url = (
        TENETX_URL
        + "/api/vmcp-install/"
        + TENETX_ORG
        + "/codex/browser-adapter"
    )
    skill_url = (
        TENETX_URL
        + "/api/vmcp-install/"
        + TENETX_ORG
        + "/codex/browser-skill"
    )
    if not _codex_browser_bundle_url_is_trusted(adapter_url):
        raise ValueError("browser_adapter_url_untrusted")
    if not _codex_browser_bundle_url_is_trusted(skill_url):
        raise ValueError("browser_skill_url_untrusted")

    # Fetch and verify the complete pair before replacing either live file.
    adapter_text = _codex_browser_bundle_get(adapter_url)
    skill_text = _codex_browser_bundle_get(skill_url)
    if hashlib.sha256(adapter_text.encode("utf-8")).hexdigest() != expected_adapter:
        raise ValueError("browser_adapter_checksum_mismatch")
    if hashlib.sha256(skill_text.encode("utf-8")).hexdigest() != expected_skill:
        raise ValueError("browser_skill_checksum_mismatch")

    _codex_browser_bundle_write(adapter_path, adapter_text)
    _codex_browser_bundle_write(skill_path, skill_text)
    return True

# Local fail-safe: when False (default), API-down = allow everything.
LOCAL_FAILSAFE = os.environ.get("TENETX_LOCAL_FAILSAFE", "").strip().lower() in ("1", "true", "yes")

FAIL_MODE = os.environ.get("TENETX_FAIL_MODE", "open").lower()
if FAIL_MODE not in ("open", "closed", "tiered"):
    FAIL_MODE = "open"


def _apply_cached_runtime_policy() -> None:
    """Let the auto-updater's cached fail-mode override baked-in env vars.

    The Codex wrapper bakes TENETX_FAIL_MODE at install time. The updater
    refreshes .update-state.json on every version-check, so admin policy
    changes propagate without a reinstall.
    """
    global FAIL_MODE, LOCAL_FAILSAFE
    try:
        script_path = os.path.abspath(__file__)
    except Exception:
        return
    script_dir = os.path.dirname(script_path)
    parent_dir = os.path.dirname(script_dir)
    grandparent_dir = os.path.dirname(parent_dir)
    if os.path.basename(script_dir) == "current":
        hook_home = parent_dir
    elif os.path.basename(parent_dir) == "versions":
        hook_home = grandparent_dir
    else:
        hook_home = script_dir
    state_path = os.path.join(hook_home, ".update-state.json")
    try:
        with open(state_path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
    except Exception:
        return
    if not isinstance(state, dict):
        return
    cached_fail_mode = str(state.get("runtime_fail_mode") or "").strip().lower()
    if cached_fail_mode in ("open", "closed", "tiered"):
        FAIL_MODE = cached_fail_mode
    if "local_failsafe" in state:
        LOCAL_FAILSAFE = bool(state.get("local_failsafe"))


_apply_cached_runtime_policy()

# Resolved below: agent-scoped sources (token file, .current pointer, newest
# per-agent token file) first; the generic TENETX_VMCP_TOKEN env var is only a
# last resort. A stale token inherited from another agent's era must never
# shadow this codex install's own credential (wrong hook_type -> 401 on every
# request, session invisible).
VMCP_TOKEN = ""
VMCP_TOKEN_ENV_FALLBACK = os.environ.get("TENETX_VMCP_TOKEN", "")
VMCP_TOKEN_FILE = os.environ.get("TENETX_VMCP_TOKEN_FILE", "")
VMCP_SENDER_KEY_FILE = os.environ.get("TENETX_VMCP_SENDER_KEY_FILE", "")
VMCP_SENDER_KEY_ID = os.environ.get("TENETX_VMCP_SENDER_KEY_ID", "")
DEBUG_ENABLED = os.environ.get("TENETX_VMCP_DEBUG", "").strip().lower() in ("1", "true", "yes")
LOG_PATH = os.path.expanduser("~/.tenetx/logs/vmcp_codex.log")
INSECURE_TLS = os.environ.get("TENETX_TLS_INSECURE", "").strip().lower() in ("1", "true", "yes")
POSTURE_HEALTHY_VALUE = "healthy"
POSTURE_UNHEALTHY_VALUE = "unhealthy"
POSTURE_POSIX_USER_MARKER_PATH = "$HOME/.tenetx/posture/ai-hook-health.txt"
POSTURE_POSIX_USER_DETAILS_PATH = "$HOME/.tenetx/posture/ai-hook-health.json"
POSTURE_POSIX_USER_HEALTHY_SENTINEL_PATH = "$HOME/.tenetx/posture/ai-hook-healthy.ok"
POSTURE_WINDOWS_USER_MARKER_PATH = "%USERPROFILE%\\.tenetx\\posture\\ai-hook-health.txt"
POSTURE_WINDOWS_USER_DETAILS_PATH = "%USERPROFILE%\\.tenetx\\posture\\ai-hook-health.json"
POSTURE_WINDOWS_USER_HEALTHY_SENTINEL_PATH = "%USERPROFILE%\\.tenetx\\posture\\ai-hook-healthy.ok"
POSTURE_DEFAULT_MARKER_PATH = POSTURE_WINDOWS_USER_MARKER_PATH if os.name == "nt" else POSTURE_POSIX_USER_MARKER_PATH
POSTURE_DEFAULT_DETAILS_PATH = POSTURE_WINDOWS_USER_DETAILS_PATH if os.name == "nt" else POSTURE_POSIX_USER_DETAILS_PATH
POSTURE_DEFAULT_HEALTHY_SENTINEL_PATH = POSTURE_WINDOWS_USER_HEALTHY_SENTINEL_PATH if os.name == "nt" else POSTURE_POSIX_USER_HEALTHY_SENTINEL_PATH
POSTURE_MARKER_PATH = os.environ.get("TENETX_POSTURE_MARKER_PATH", POSTURE_DEFAULT_MARKER_PATH)
POSTURE_DETAILS_PATH = os.environ.get("TENETX_POSTURE_DETAILS_PATH", POSTURE_DEFAULT_DETAILS_PATH)
POSTURE_HEALTHY_SENTINEL_PATH = os.environ.get("TENETX_POSTURE_HEALTHY_SENTINEL_PATH", POSTURE_DEFAULT_HEALTHY_SENTINEL_PATH)
try:
    POSTURE_TTL_SECONDS = int(os.environ.get("TENETX_POSTURE_TTL_SECONDS", "300"))
except ValueError:
    POSTURE_TTL_SECONDS = 300
MAX_RESPONSE_SCAN_BYTES = 1 * 1024 * 1024
PERMISSION_ASK_MODE = os.environ.get("TENETX_CODEX_PERMISSION_ASK_MODE", "deny").strip().lower()
NATIVE_PROMPT_OVERRIDE = os.environ.get("TENETX_CODEX_NATIVE_PROMPT", "").strip().lower()
SKIP_WATCHER_DISABLED = os.environ.get("TENETX_CODEX_SKIP_WATCHER_DISABLE", "").strip().lower() in ("1", "true", "yes")
PENDING_ASK_TTL_SECONDS = int(os.environ.get("TENETX_CODEX_PENDING_ASK_TTL_SECONDS", "600"))
SKIP_WATCHER_SECONDS = int(os.environ.get("TENETX_CODEX_SKIP_WATCHER_SECONDS", "120"))
SKIP_WATCHER_INTERVAL_SECONDS = float(os.environ.get("TENETX_CODEX_SKIP_WATCHER_INTERVAL_SECONDS", "1.0"))
CODEX_SESSION_SCAN_BYTES = int(os.environ.get("TENETX_CODEX_SESSION_SCAN_BYTES", str(2 * 1024 * 1024)))
WORK_ITEM_KEY_RE = re.compile(r"\b([A-Z][A-Z0-9]{1,15}-\d{1,8})\b", re.IGNORECASE)
_PATCH_TARGET_RE = re.compile(
    r"^\*\*\* (?:Add File|Update File|Delete File|Move to):\s+(.+?)\s*$",
    re.MULTILINE,
)
CODEX_NATIVE_PROMPT_PREFIX_RULES = (
    ("rm",),
    ("curl",),
    ("wget",),
    ("ssh",),
    ("scp",),
    ("sftp",),
    ("rsync",),
    ("git", "push"),
    ("docker",),
    ("docker-compose",),
    ("kubectl",),
    ("helm",),
    ("terraform",),
    ("aws",),
    ("gcloud",),
    ("az",),
    ("psql",),
    ("mysql",),
    ("sqlite3",),
    ("gh", "api"),
)

parsed_url = urlparse(TENETX_URL)
hostname = (parsed_url.hostname or "").lower()
# Auto-insecure only for true loopback or *.local.tenetx.ai dev hosts. The
# previous ".local." substring matched any mDNS-style host (and crafted names
# such as attacker.local.evil.com), silently disabling TLS verification.
if hostname in ("localhost", "127.0.0.1", "::1") or hostname == "local.tenetx.ai" or hostname.endswith(".local.tenetx.ai"):
    INSECURE_TLS = True

SSL_CONTEXT = ssl._create_unverified_context() if INSECURE_TLS else None
USER_AGENT = "TenetX-VMCP-Hook/1.0"


def _surface_from_bundle_id(bundle):
    """Only agent-owned desktop apps are trustworthy here: IDE bundle ids
    (com.microsoft.VSCode, Cursor's) are inherited by their integrated
    TERMINALS too, so they cannot distinguish "extension" from "CLI run
    inside the IDE terminal" and must not be mapped."""
    b = (bundle or "").lower()
    if b.startswith("com.openai.chat"):
        return "chatgpt-app"
    if b.startswith("com.anthropic.claude"):
        return "desktop"
    return None


def _surface_from_cmd(cmd):
    """Classify one ancestor process command path. The first ancestor that IS
    the codex binary decides: its install location tells the surface (IDE
    extension dir, ChatGPT desktop app bundle, or a plain PATH install = CLI
    — even inside an IDE's integrated terminal). Mirrors
    tenetx.vmcp.hook_template so audit_logs.client_surface stays consistent
    across all VMCP hook types."""
    low = (cmd or "").strip().lower()
    if not low:
        return None
    if ".vscode/extensions/" in low or ".vscode-server/extensions/" in low or ".vscode-insiders/extensions/" in low:
        return "vscode"
    if ".cursor/extensions/" in low or ".cursor-server/extensions/" in low:
        return "cursor-desktop"
    if "chatgpt.app/" in low or "codex framework" in low:
        return "chatgpt-app"
    if "claude.app/" in low or "claudefordesktop" in low:
        return "desktop"
    if "jetbrains" in low or "/idea" in low or "pycharm" in low or "webstorm" in low or "goland" in low:
        return "jetbrains"
    base = low.rsplit("/", 1)[-1]
    if base in ("codex", "codex.exe", "claude", "claude.exe", "copilot", "copilot.exe", "cursor-agent"):
        return "cli"
    if "windsurf" in low:
        return "windsurf"
    if "code helper" in low or low.endswith("/code") or "cursor helper" in low or "cursor.app/" in low:
        return "cursor-desktop" if "cursor" in low else "vscode"
    return None


def _parent_chain(max_hops=5):
    chain = []
    try:
        import subprocess as _sp
        pid = os.getppid()
        for _ in range(max_hops):
            if not pid or pid <= 1:
                break
            out = _sp.run(
                ["ps", "-p", str(pid), "-o", "ppid=,comm="],
                capture_output=True, text=True, timeout=1,
            ).stdout.strip()
            if not out:
                break
            parts = out.split(None, 1)
            if len(parts) < 2:
                break
            chain.append(parts[1])
            pid = int(parts[0])
    except Exception:
        pass
    return chain


def _detect_client_surface():
    """Which client surface launched Codex: "cli", "vscode", "cursor",
    "jetbrains", "windsurf", "chatgpt-app" (ChatGPT desktop app), or
    "unknown". Ancestor executable paths are the authoritative signal; env
    hints are only a fallback where `ps` is unavailable (e.g. Windows),
    because VSCODE_*/TERM_PROGRAM also leak into IDE integrated terminals."""
    try:
        surface = _surface_from_bundle_id(os.environ.get("__CFBundleIdentifier", ""))
        if surface:
            return surface
        for cmd in _parent_chain():
            surface = _surface_from_cmd(cmd)
            if surface:
                return surface
        if os.environ.get("VSCODE_PID") or os.environ.get("VSCODE_GIT_IPC_HANDLE") or os.environ.get("VSCODE_INJECTION"):
            return "vscode"
        term_program = (os.environ.get("TERM_PROGRAM") or "").lower()
        if term_program == "vscode":
            return "vscode"
        if term_program == "cursor":
            return "cursor"
        if "jetbrains" in term_program or os.environ.get("TERMINAL_EMULATOR", "").lower() == "jetbrains-jediterm":
            return "jetbrains"
        return "cli"
    except Exception:
        return "unknown"


CLIENT_SURFACE = _detect_client_surface()


def _truthy(value):
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


def _falsey(value):
    return str(value or "").strip().lower() in ("0", "false", "no", "off")


def _codex_config_text():
    path = os.path.expanduser("~/.codex/config.toml")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except Exception:
        return ""


def _codex_approvals_disabled(config_text=None):
    text = _codex_config_text() if config_text is None else str(config_text or "")
    return bool(re.search(r"(?m)^\s*approval_policy\s*=\s*['\"]never['\"]\s*$", text))


def _codex_rule_prompts_enabled(config_text=None):
    text = _codex_config_text() if config_text is None else str(config_text or "")
    if _codex_approvals_disabled(text):
        return False
    return bool(
        re.search(r"(?m)^\s*approval_policy\s*=.*\brules\s*=\s*true\b", text)
        or re.search(r"(?m)^\s*rules\s*=\s*true\s*$", text)
    )


def _codex_mcp_prompts_enabled(config_text=None):
    text = _codex_config_text() if config_text is None else str(config_text or "")
    if _codex_approvals_disabled(text):
        return False
    return bool(
        re.search(r"(?m)\bmcp_elicitations\s*=\s*true\b", text)
        or re.search(r"(?m)\brequest_permissions\s*=\s*true\b", text)
    )


def _tenetx_codex_rules_installed():
    path = os.path.expanduser("~/.codex/rules/tenetx.rules")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except Exception:
        return False
    return "prefix_rule" in text and 'decision="prompt"' in text


def _server_expects_codex_native_prompt(result):
    if not isinstance(result, dict):
        return False
    return (
        result.get("native_prompt_expected") is True
        or result.get("ask_delivery") == "codex_native_permission_request"
        or result.get("codex_pretool_behavior") == "defer"
    )


def _codex_native_prompt_available(result=None, tool_name=None, tool_input=None):
    if _falsey(NATIVE_PROMPT_OVERRIDE):
        return False
    config_text = _codex_config_text()
    if _codex_approvals_disabled(config_text):
        return False
    if _truthy(NATIVE_PROMPT_OVERRIDE):
        return True
    if PERMISSION_ASK_MODE != "defer":
        return False
    if normalize_tool_name(tool_name) == "MCP":
        return _codex_mcp_prompts_enabled(config_text)
    return _codex_rule_prompts_enabled(config_text) and _tenetx_codex_rules_installed()


def _codex_command_prefix_matches_native_prompt(command):
    if not isinstance(command, str) or not command.strip():
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    lowered = [str(token).strip().lower() for token in tokens if str(token).strip()]
    if not lowered:
        return False
    for pattern in CODEX_NATIVE_PROMPT_PREFIX_RULES:
        if len(lowered) >= len(pattern) and tuple(lowered[:len(pattern)]) == pattern:
            return True
    return False


def _codex_native_mcp_tool_can_prompt(tool_name, tool_input):
    if normalize_tool_name(tool_name) != "MCP" or not isinstance(tool_input, dict):
        return False
    raw_tool_name = str(tool_input.get("raw_tool_name") or tool_name or "").strip()
    if raw_tool_name.startswith("mcp__"):
        return True
    return bool(tool_input.get("server_id") and tool_input.get("mcp_tool_name"))


def _codex_pretool_ask_can_defer(result, tool_name, tool_input):
    if not _server_expects_codex_native_prompt(result):
        return False
    if not _codex_native_prompt_available(result, tool_name, tool_input):
        return False
    normalized_tool = normalize_tool_name(tool_name)
    if normalized_tool == "MCP":
        # A PreToolUse notification is not evidence that Codex will render a
        # permission UI. Real node_repl runs continued directly to PostToolUse
        # and were incorrectly recorded as approved. Only PermissionRequest is
        # an authoritative native approval boundary; a PreToolUse ASK must
        # remain blocked.
        return False
    if normalized_tool != "Bash" or not isinstance(tool_input, dict):
        return False
    return _codex_command_prefix_matches_native_prompt(str(tool_input.get("command") or ""))


if not VMCP_TOKEN and VMCP_TOKEN_FILE:
    try:
        with open(VMCP_TOKEN_FILE, "r", encoding="utf-8") as f:
            VMCP_TOKEN = f.read().strip()
    except Exception:
        VMCP_TOKEN = ""

if not VMCP_TOKEN:
    token_dir = os.path.expanduser("~/.tenetx/vmcp_tokens")
    current_pointer = os.path.join(token_dir, f"{TENETX_ORG}_codex.current")
    try:
        with open(current_pointer, "r", encoding="utf-8") as f:
            pointed = os.path.expanduser(f.read().strip())
        with open(pointed, "r", encoding="utf-8") as f:
            VMCP_TOKEN = f.read().strip()
    except Exception:
        VMCP_TOKEN = ""

if not VMCP_TOKEN:
    try:
        import glob
        candidates = sorted(
            glob.glob(os.path.join(token_dir, f"{TENETX_ORG}_codex_*.token")),
            key=lambda path: os.path.getmtime(path),
            reverse=True,
        )
    except Exception:
        candidates = []
    for candidate in candidates:
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                VMCP_TOKEN = f.read().strip()
        except Exception:
            VMCP_TOKEN = ""
        if VMCP_TOKEN:
            break

if not VMCP_TOKEN:
    VMCP_TOKEN = VMCP_TOKEN_ENV_FALLBACK


def _load_token():
    """Return the credential resolved from environment or managed token files."""
    return VMCP_TOKEN


# Shared hook-source aliases. Codex resolves the same concepts under its own
# native names, while the reusable remediation helper intentionally targets a
# small cross-agent contract.
ORG_SLUG = TENETX_ORG
API_URL = TENETX_URL
HOOK_TYPE = "codex"


def _signin_remediation(token=None):
    """Actionable sign-in line when there is no local TenetX credential.

    Returns None when a token already exists, so a genuine API/network outage
    keeps its own "unavailable" message rather than telling an already-signed-in
    developer to log in. A clicked URL alone cannot mint the local token, so the
    message leads with the working CLI command — including --api-base so
    staging / self-hosted orgs sign in to the right backend — and offers the
    onboarding page only as help. Pass the already-loaded `token` to skip a
    redundant token-file scan; falls back to _load_token() when omitted.
    """
    if token is None:
        token = _load_token()
    if token:
        return None
    ide = HOOK_TYPE.replace("-", "_")
    return (
        "🛡  TenetX sign-in required - no local credential. "
        "Run:  tenetx login --org " + ORG_SLUG + " --ides " + ide
        + " --api-base " + API_URL
        + "   (help: " + API_URL + "/onboarding)"
    )


def _signin_nudge_once():
    """Show the observe-mode sign-in nudge at most once per hour per hook.

    Observe-mode fail-open invokes the hook on every tool call; without this
    guard the nudge would repeat on each action. Blocking (fail-closed) paths do
    not use this — there the message must show every time the action is denied.
    """
    try:
        marker = Path.home() / ".tenetx" / "signin_nudge" / (ORG_SLUG + "_" + HOOK_TYPE + ".ts")
        now = time.time()
        if marker.exists():
            age = now - marker.stat().st_mtime
            # 0 <= age < 1h: shown recently, stay quiet. A negative age (clock
            # stepped backward via NTP/DST) is treated as stale so a bad clock
            # can't suppress the nudge forever.
            if 0 <= age < 3600:
                return False
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(str(now), encoding="utf-8")
        return True
    except OSError:
        # Can't persist the throttle (e.g. read-only HOME): stay quiet rather
        # than re-nudging on every single tool call.
        return False



def _hook_attestation_payload():
    if not VMCP_TOKEN:
        return None
    token_hash = hashlib.sha256(VMCP_TOKEN.encode("utf-8")).hexdigest()
    timestamp = int(time.time())
    nonce = hashlib.sha256(
        f"{timestamp}|{os.getpid()}|{time.time_ns()}".encode("utf-8")
    ).hexdigest()[:24]
    control_fingerprint = hashlib.sha256(
        "|".join((
            "tenetx-vmcp-hook-v1",
            TENETX_ORG,
            "codex",
            token_hash[:16],
            CLIENT_SURFACE,
        )).encode("utf-8")
    ).hexdigest()
    subject = "|".join((TENETX_ORG, "codex", control_fingerprint, str(timestamp), nonce))
    signature = hmac.new(token_hash.encode("utf-8"), subject.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "schema": "tenetx/hook-attestation/v1",
        "status": "healthy",
        "org_slug": TENETX_ORG,
        "hook_type": "codex",
        "control_fingerprint": control_fingerprint,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": signature,
    }


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sender_proof_body(payload):
    return {
        str(key): value
        for key, value in payload.items()
        if str(key) not in ("vmcp_sender_proof", "sender_proof", "tenetx_sender_proof")
    }


def _sender_key_file():
    key_file = str(VMCP_SENDER_KEY_FILE or "").strip()
    if key_file:
        return os.path.expanduser(key_file)
    key_dir = os.path.expanduser("~/.tenetx/vmcp_keys")
    current_pointer = os.path.join(key_dir, TENETX_ORG + "_codex.current")
    try:
        with open(current_pointer, "r", encoding="utf-8") as handle:
            pointed = os.path.expanduser(handle.read().strip())
        if os.path.isfile(pointed):
            return pointed
    except Exception:
        pass
    try:
        import glob
        candidates = sorted(
            glob.glob(os.path.join(key_dir, TENETX_ORG + "_codex_*.pem")),
            key=lambda path: os.path.getmtime(path),
            reverse=True,
        )
    except Exception:
        candidates = []
    return candidates[0] if candidates else ""


def _sender_key_id():
    key_id = str(VMCP_SENDER_KEY_ID or "").strip()
    if key_id:
        return key_id
    key_dir = os.path.expanduser("~/.tenetx/vmcp_keys")
    current_pointer = os.path.join(key_dir, TENETX_ORG + "_codex.current_key_id")
    try:
        with open(current_pointer, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except Exception:
        return ""


def _sender_proof_payload(path, payload):
    if not VMCP_TOKEN or not path:
        return None
    key_file = _sender_key_file()
    key_id = _sender_key_id()
    if not key_file or not key_id:
        return None
    timestamp = int(time.time())
    nonce = hashlib.sha256(
        ("sender|%s|%s|%s" % (timestamp, os.getpid(), time.time_ns())).encode("utf-8")
    ).hexdigest()
    body_hash = hashlib.sha256(_canonical_json(_sender_proof_body(payload)).encode("utf-8")).hexdigest()
    proof = {
        "schema": "tenetx/vmcp-sender-proof/v1",
        "alg": "ES256",
        "kid": key_id,
        "org": TENETX_ORG,
        "hook_type": "codex",
        "htm": "POST",
        "htu": path,
        "ath": hashlib.sha256(VMCP_TOKEN.encode("utf-8")).hexdigest(),
        "body_sha256": body_hash,
        "iat": timestamp,
        "jti": nonce,
    }
    try:
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", key_file],
            input=_canonical_json(proof).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except Exception:
        return None
    if result.returncode != 0 or not result.stdout:
        return None
    proof["signature"] = _b64url(result.stdout)
    return proof


def _json_payload(payload, path=None):
    attestation = _hook_attestation_payload()
    if attestation:
        payload.setdefault("hook_attestation", attestation)
    sender_proof = _sender_proof_payload(path, payload)
    if sender_proof:
        payload.setdefault("vmcp_sender_proof", sender_proof)
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


# HIGH-RISK patterns that should FAIL CLOSED (block if API unreachable)
HIGH_RISK_PATTERNS = {
    "Bash": [
        r"\b(?:cat|head|tail|less|more|sed|awk|grep|rg|base64|xxd|strings)\b.*(?:\.env\.(?:prod|production)|\.ssh/|\.aws/|\.kube/config|\.git-credentials|terraform\.tfstate|secrets?/|credentials|token)",
        r"rm\s+-rf", r"\brm\s+-(?=[A-Za-z]*r)(?=[A-Za-z]*f)[A-Za-z]+", r"rm\s+-r\s+/", r"rmdir",
        r"\brm\s+-[A-Za-z]*f[A-Za-z]*\s+(?:\.?/?logs?/.*\.log|/var/log/)",
        r"\bgit\s+push\b(?![^\n;&|]*\s(?:--dry-run|--dryrun|--check|--simulate|--noop)(?:\s|$))[^\n;&|]*(?:--force(?:-with-lease)?|-f)\b",
        r"\bgit\s+push\b(?![^\n;&|]*\s(?:--dry-run|--dryrun|--check|--simulate|--noop)(?:\s|$))[^\n;&|]*(?:--delete\b|:[^\s;&|]+)",
        r"\bgit\s+(?:branch|tag)\s+(?:-d|-D|--delete)\b",
        r"\bgit\s+reset\b[^\n;&|]*--hard\b",
        r"git\s+clean\s+-[A-Za-z]*f",
        r"\bgit\s+tag\s+(?!(?:-d|--delete|-l|--list)\b)\S+",
        r"docker\s+(volume\s+(rm|prune)|system\s+prune|rm\s+.*\$)",
        r"docker-compose\s+down\s+-v",
        r"\bsqlite3?\b.*\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW)\b",
        r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW)\b",
        r"curl\s+.*(?:-X\s+POST|--data(?:-raw|-binary|-ascii)?|-d\s+|--json|--form(?:-string)?|-F\s+|--upload-file|-T\s+)",
        r"wget\s+(--post-data|--post-file)",
        r"\bnc\b|\bncat\b|\bnetcat\b",
        r"\b(?:uname\s+-a|ifconfig\b|ip\s+(?:addr|a|route|r)\b|whoami\b|hostname\b)",
        r"\b(?:pip[3]?|python[23]?\s+-m\s+pip)\s+download\b",
        r"nc\s+.*-e\s+",
        r"scp\s+.*@(?!localhost|127\.0\.0\.1)",
        r"rsync\s+.*@(?!localhost|127\.0\.0\.1)",
        r"sftp\s+.*@(?!localhost|127\.0\.0\.1)",
        r"ssh\s+.*@(?!localhost|127\.0\.0\.1).*['\x22].*['\x22]",
        r"git\s+remote\s+add\s+",
        r"git\s+push\s+.*@(?!localhost|127\.0\.0\.1)",
        r"python[23]?\s+(-m\s+)?http\.server",
        r"python[23]?\s+(-m\s+)?SimpleHTTPServer",
        r"chmod\s+777\s+/",
        r"chmod\s+(?:777|[0-7]*[2367][0-7]{2}|(?:[augo]*\+|[augo]*=)[rwx]*w[rwx]*)\s+(?:\.ssh/|\.aws/|\.kube/|\.env\b|\.env\.|secrets?/|.*(?:credential|secret|token|private-key|id_rsa|id_ed25519))",
        r"chown\s+.*\s+/",
        r"mkfs(?:\.[A-Za-z0-9_-]+)?", r"dd\s+.*of=/dev/",
        r":(\s*)\{", r"shutdown|reboot|halt|poweroff",
        # Guard self-protection: shell tamper with our own hook kill-switch.
        r"\.codex/(?:hooks\.json|config\.toml|config\.json)",
        r"\.claude/(?:settings(?:\.local)?\.json|hooks/)", r"\.claude\.json",
        r"\.cursor/(?:hooks\.json|mcp\.json)",
        r"\.tenetx/(?:hooks|vmcp_tokens|vmcp_keys|managed|guard)",
        r"tenetx-guard\.py",
        r"\b(?:CODEX_HOME|CLAUDE_CONFIG_DIR|CLAUDE_HOME|CURSOR_HOME|CURSOR_CONFIG_DIR|TENETX_HOOKS_DIR|TENETX_GUARD_DIR|TENETX_GUARD_PATH|TENETX_VMCP_TOKEN_FILE|TENETX_VMCP_SENDER_KEY_FILE)\s*=",
        r"(?:codex_)?hooks\s*=\s*false\b",
    ],
    "Write": [
        r"secrets",
        r"\.aws/", r"\.ssh/", r"\.env", r"secrets?\.",
        r"credentials?\.", r"\.kube/config", r"\.npmrc",
        r"\.pypirc", r"\.docker/config", r"\.gnupg/",
        r"\.git-credentials", r"\.netrc", r"terraform\.tfstate",
        r"\.yarnrc", r"\.key$",
        r"CLAUDE\.md$", r"\.claude\.json", r"\.claude/",
        r"\.codex/(?:hooks\.json|config\.toml|config\.json|plugins/|rules/)",
        r"\.tenetx/",
        r"\.cursor/(?:hooks\.json|mcp\.json|rules/)", r"\.cursorrules",
    ],
    "Edit": [
        r"secrets",
        r"\.aws/", r"\.ssh/", r"\.env", r"secrets?\.", r"credentials?\.",
        r"\.kube/config", r"\.gnupg/", r"\.git-credentials", r"\.netrc",
        r"CLAUDE\.md$", r"\.claude\.json", r"\.claude/",
        r"\.codex/(?:hooks\.json|config\.toml|config\.json|plugins/|rules/)",
        r"\.tenetx/",
        r"\.cursor/(?:hooks\.json|mcp\.json|rules/)", r"\.cursorrules",
    ],
    "Read": [
        r"secrets",
        r"\.aws/credentials", r"\.ssh/id_", r"\.env\.prod", r"/etc/shadow",
        r"\.gnupg/", r"terraform\.tfstate", r"\.git-credentials", r"\.netrc",
    ],
}


_CODEX_APP_PREFIXES = tuple(sorted((
    "atlassian_rovo", "codex_document_control", "google_calendar",
    "google_drive", "computer_use", "figma", "github", "gmail",
    "sites", "slack",
), key=len, reverse=True))


def connector_slug(value):
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def split_codex_app_action(value):
    text = connector_slug(value)
    for app in _CODEX_APP_PREFIXES:
        prefix = app + "_"
        if text.startswith(prefix):
            return app, text[len(prefix):]
    if "_" in text:
        return tuple(text.split("_", 1))
    return "", text


def parse_native_mcp_tool_name(tool_name, tool_input=None):
    """Normalize native and Codex-app connector identities for policy matching."""
    text = str(tool_name or "").strip()
    data = tool_input if isinstance(tool_input, dict) else {}
    invocation = data.get("invocation") if isinstance(data.get("invocation"), dict) else {}
    connector_server = connector_slug(
        invocation.get("server") or data.get("connector_server") or data.get("server")
    )
    app = connector_slug(data.get("connector_app") or data.get("app_name"))
    connector_action = connector_slug(data.get("connector_action") or data.get("action_name"))
    connector_tool = str(
        invocation.get("tool") or data.get("connector_tool_name") or data.get("tool") or ""
    ).strip()

    display_parts = [part.strip() for part in re.split(r"\s*[·›>]\s*", text) if part.strip()]
    if len(display_parts) >= 3 and connector_slug(display_parts[0]) == "codex_apps":
        connector_server = connector_server or "codex_apps"
        app = app or connector_slug(display_parts[-2])
        connector_action = connector_action or connector_slug(display_parts[-1])

    canonical_action = ""
    dotted_tool = connector_tool or (text if "." in text and not text.startswith("mcp__") else "")
    if "." in dotted_tool:
        dotted_app, dotted_action = dotted_tool.split(".", 1)
        dotted_app = connector_slug(dotted_app)
        dotted_action = connector_slug(dotted_action)
        connector_server = connector_server or dotted_app
        if dotted_app == "codex_apps":
            inferred_app, inferred_action = split_codex_app_action(dotted_action)
            app = app or inferred_app
            connector_action = connector_action or dotted_action
            canonical_action = inferred_action
        else:
            app = app or dotted_app
            connector_action = connector_action or dotted_action
            canonical_action = dotted_action

    if text.startswith("codex_apps_") and not text.startswith("mcp__"):
        native_tool = connector_slug(text[len("codex_apps_"):])
        inferred_app, inferred_action = split_codex_app_action(native_tool)
        connector_server = connector_server or "codex_apps"
        app = app or inferred_app
        connector_action = connector_action or native_tool
        canonical_action = canonical_action or inferred_action

    if text.startswith("mcp__"):
        parts = text.split("__", 2)
        if len(parts) != 3 or not parts[1] or not parts[2]:
            return {"raw_tool_name": text}
        native_server = connector_slug(parts[1])
        native_tool = connector_slug(parts[2])
        connector_server = connector_server or native_server
        if native_server == "codex_apps":
            inferred_app, inferred_action = split_codex_app_action(native_tool)
            app = app or inferred_app
            connector_action = connector_action or native_tool
            canonical_action = inferred_action
        else:
            app = app or native_server
            connector_action = connector_action or native_tool
            canonical_action = native_tool
    elif not canonical_action:
        canonical_action = connector_action

    if not app or not canonical_action:
        return {}
    app_prefix = app + "_"
    if canonical_action.startswith(app_prefix):
        canonical_action = canonical_action[len(app_prefix):]
    return {
        "raw_tool_name": text,
        "connector_server": connector_server or app,
        "connector_app": app,
        "connector_action": connector_action or canonical_action,
        "connector_tool_name": connector_tool or text,
        "server_id": app,
        "mcp_server_id": app,
        "mcp_tool_name": canonical_action,
    }


def extract_patch_targets(patch):
    """Extract target paths from an apply_patch payload."""
    if not isinstance(patch, str) or not patch.strip():
        return {}
    targets = []
    operations = []
    for match in _PATCH_TARGET_RE.finditer(patch):
        line = match.group(0)
        path = match.group(1).strip()
        if not path:
            continue
        if path not in targets:
            targets.append(path)
        op = line.split(":", 1)[0].replace("*** ", "").strip().lower().replace(" ", "_")
        if op not in operations:
            operations.append(op)
    if not targets:
        return {}
    data = {"target_paths": targets}
    if operations:
        data["patch_operations"] = operations
    data["patch_operation"] = operations[0] if len(operations) == 1 else "mixed"
    return data


def iter_file_targets(tool_input):
    for key in ("file_path", "path", "target_path"):
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            yield value.strip()
    targets = tool_input.get("target_paths")
    if isinstance(targets, list):
        for value in targets:
            if isinstance(value, str) and value.strip():
                yield value.strip()


def is_high_risk(tool_name, tool_input):
    tool_name = normalize_tool_name(tool_name)
    if tool_name in ("Browser", "MCP", "CodexExec"):
        return True
    tool_input = normalize_tool_input(tool_name, tool_input)
    patterns = HIGH_RISK_PATTERNS.get(tool_name, [])
    if not patterns:
        return False
    if tool_name == "Bash":
        check_value = tool_input.get("command", "")
    elif tool_name in ("Read", "Write", "Edit"):
        check_value = "\n".join(iter_file_targets(tool_input))
    else:
        return False
    for pattern in patterns:
        if re.search(pattern, check_value, re.IGNORECASE):
            return True
    return False


import re as _gsp_re

# The local guard protects only the small root of trust required for the next
# invocation: installed hook wiring/runtime, authentication/sender-proof
# material, and the guard script itself. Ordinary agent configuration remains
# server-authoritative while TenetX is reachable.
_GSP_LOCAL_KILLSWITCH_RE = _gsp_re.compile(
    r"(?:^|[\\/])\.codex[\\/]hooks\.json\b"
    r"|(?:^|[\\/])\.claude[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.cursor[\\/]hooks(?:\.json|[\\/]|$)"
    r"|(?:^|[\\/])\.copilot[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.windsurf[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.qwen[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.augment[\\/]hooks(?:[\\/]|$)"
    # Mistral Vibe Code declares hooks in .vibe/hooks.toml, so the FILE is
    # the killswitch here -- unlike every JSON-settings agent above, where the
    # hooks directory alone is enough.
    r"|(?:^|[\\/])\.vibe[\\/]hooks(?:\.toml|[\\/]|$)"
    r"|(?:^|[\\/])\.kiro[\\/]hooks(?:[\\/]|$)"
    # Cline registers a hook by PLACING AN EXECUTABLE named after the event
    # in one of these directories -- there is no settings file to protect,
    # so the directory IS the wiring. ~/Documents/Cline/Hooks is where
    # TenetX installs; the others are the roots Cline also scans, so a
    # write there can add a competing hook or shadow ours.
    r"|(?:^|[\\/])\.cline[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.clinerules[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])Documents[\\/]Cline[\\/](?:Hooks|Plugins)(?:[\\/]|$)"
    r"|(?:^|[\\/])\.hermes[\\/](?:hooks|agent-hooks|plugins)(?:[\\/]|$)"
    r"|(?:^|[\\/])\.hermes[\\/]config\.ya?ml\b"
    r"|(?:^|[\\/])\.hermes[\\/]shell-hooks-allowlist\.json\b"
    r"|(?:^|[\\/])\.tenetx[\\/](?:hooks|vmcp_tokens|vmcp_keys|attestations)(?:[\\/]|$)"
    r"|(?:^|[\\/])(?:Library[\\/]Application Support|etc|ProgramData)[\\/]TenetX[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])(?:programdata|library[\\/]application support|etc)[\\/]tenetx[\\/]hooks(?:[\\/]|$)"
    r"|\$env:ProgramData[\\/]TenetX[\\/]hooks(?:[\\/]|$)"
    r"|%ProgramData%[\\/]TenetX[\\/]hooks(?:[\\/]|$)"
    r"|[A-Za-z]:[\\/]ProgramData[\\/]TenetX[\\/]hooks(?:[\\/]|$)"
    r"|tenetx-guard\.py\b|tenetx-hook\.py\b"
    r"|tenetx-guard\.(?:sh|ps1|cmd)\b",
    _gsp_re.IGNORECASE,
)
# Local read protection is restricted to secret authentication and
# sender-proof material. Reading non-secret guard source is server-governed:
# blocking open-source inspection locally would be security by obscurity and
# would interfere with support and integrity verification.
_GSP_LOCAL_PROTECTED_READ_RE = _gsp_re.compile(
    r"(?:^|[\\/])\.tenetx[\\/](?:vmcp_tokens|vmcp_keys)(?:[\\/]|$)",
    _gsp_re.IGNORECASE,
)
# Relocating where the agent resolves hooks/config on next launch neutralizes
# the guard without touching a protected file.
_GSP_REDIRECT_RE = _gsp_re.compile(
    r"\b(?:CODEX_HOME|CLAUDE_CONFIG_DIR|CLAUDE_HOME|CURSOR_HOME|CURSOR_CONFIG_DIR"
    r"|TENETX_HOOKS_DIR|TENETX_GUARD_DIR|TENETX_GUARD_PATH|TENETX_USER_HOOK"
    r"|TENETX_MANAGED_RUNTIME_MISSING_MODE|TENETX_RUNTIME_MISSING_MODE"
    r"|TENETX_FAIL_MODE|TENETX_LOCAL_FAILSAFE|TENETX_VMCP_TOKEN"
    r"|TENETX_VMCP_TOKEN_FILE|TENETX_VMCP_SENDER_KEY_FILE)"
    r"\s*=\s*\S"
    r"|\$env:(?:TENETX_USER_HOOK|TENETX_MANAGED_RUNTIME_MISSING_MODE|TENETX_RUNTIME_MISSING_MODE"
    r"|TENETX_FAIL_MODE|TENETX_LOCAL_FAILSAFE|TENETX_VMCP_TOKEN|TENETX_VMCP_TOKEN_FILE|TENETX_VMCP_SENDER_KEY_FILE)"
    r"\s*=\s*\S"
    r"|os\.environ\s*\[\s*[\"'](?:TENETX_USER_HOOK|TENETX_MANAGED_RUNTIME_MISSING_MODE"
    r"|TENETX_RUNTIME_MISSING_MODE|TENETX_FAIL_MODE|TENETX_LOCAL_FAILSAFE|TENETX_VMCP_TOKEN"
    r"|TENETX_VMCP_TOKEN_FILE|TENETX_VMCP_SENDER_KEY_FILE)[\"']\s*\]\s*=\s*",
    _gsp_re.IGNORECASE,
)
# Switching the hook feature off via a config flag or settings key.
_GSP_HOOK_DISABLE_RE = _gsp_re.compile(
    r"(?:^|[\s'\"#=+/(:,])(?:codex_)?hooks\s*=\s*false\b"
    r"|disableallhooks\s*[\"']?\s*[:=]\s*[\"']?\s*true"
    r"|[\"']hooks[\"']\s*:\s*(?:false|\{\s*\})",
    _gsp_re.IGNORECASE,
)
# Weaker signal: a reference to an agent governance config dir. Scoped so the
# guard's own log dir (~/.tenetx/logs) does NOT trip it.
_GSP_LOCAL_DIR_TOKEN_RE = _gsp_re.compile(
    r"(?:^|[\s'\"=:(,/])\.codex[\\/]hooks\.json\b"
    r"|(?:^|[\s'\"=:(,/])\.(?:claude|cursor|copilot|windsurf|qwen|hermes|augment|kiro|cline|vibe)[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\s'\"=:(,/])\.vibe[\\/]hooks(?:\.toml|[\\/]|$)"
    r"|(?:^|[\s'\"=:(,/])\.clinerules[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\s'\"=:(,/])Documents[\\/]Cline[\\/]Hooks(?:[\\/]|$)"
    r"|(?:^|[\s'\"=:(,/])\.tenetx[\\/](?:hooks|vmcp_tokens|vmcp_keys|attestations)(?:[\\/]|$)",
    _gsp_re.IGNORECASE,
)

# Server-side V3 keeps the broader governance surface. These patterns are not
# embedded as local authority: they let the server classify ordinary agent
# configuration and runtime-governance changes with canonical policy reasons.
_GSP_KILLSWITCH_RE = _gsp_re.compile(
    r"(?:^|[\\/])\.codex[\\/](?:hooks\.json|config\.toml|config\.json)"
    r"|(?:^|[\\/])\.claude[\\/](?:settings(?:\.local)?\.json|hooks(?:[\\/]|$))"
    r"|(?:^|[\\/])\.claude\.json\b"
    r"|(?:^|[\\/])\.cursor[\\/](?:hooks\.json|mcp\.json)"
    r"|(?:^|[\\/])\.qwen[\\/](?:settings(?:\.local)?\.json|hooks(?:[\\/]|$)|mcp\.json)"
    r"|(?:^|[\\/])\.augment[\\/](?:settings(?:\.local)?\.json|hooks(?:[\\/]|$)|mcp\.json)"
    r"|(?:^|[\\/])\.vibe[\\/](?:hooks\.toml|config\.toml|hooks(?:[\\/]|$)"
    r"|plugins(?:[\\/]|$)|tools(?:[\\/]|$)|trusted_folders\.toml)"
    r"|(?:^|[\\/])\.kiro[\\/](?:hooks(?:[\\/]|$)|settings[\\/]|agents(?:[\\/]|$))"
    # Cline. `.clinerules` is BOTH a project rules directory and (in older
    # releases) a single rules file, so it is matched without requiring a
    # trailing separator. cline_mcp_settings.json is matched by basename
    # too: it lives under ~/.cline/data/settings, but $CLINE_DATA_DIR and
    # $CLINE_MCP_SETTINGS_PATH can move it anywhere.
    r"|(?:^|[\\/])\.cline[\\/](?:hooks(?:[\\/]|$)|plugins(?:[\\/]|$)"
    r"|rules(?:[\\/]|$)|skills(?:[\\/]|$)|data[\\/]settings(?:[\\/]|$))"
    r"|(?:^|[\\/])\.clinerules(?:[\\/]|$|\.md\b)"
    r"|(?:^|[\\/])cline_mcp_settings\.json\b"
    r"|(?:^|[\\/])Documents[\\/]Cline[\\/](?:Hooks|Plugins|Rules|Agents|Workflows)(?:[\\/]|$)"
    r"|(?:^|[\\/])\.hermes[\\/](?:config\.ya?ml|hooks(?:[\\/]|$)"
    r"|agent-hooks(?:[\\/]|$)|plugins(?:[\\/]|$)|shell-hooks-allowlist\.json)"
    r"|(?:^|[\\/])\.tenetx[\\/](?:hooks|vmcp_tokens|vmcp_keys|managed|guard|posture|attestations)(?:[\\/]|$)"
    r"|(?:^|[\\/])(?:Library[\\/]Application Support|etc|ProgramData)[\\/]TenetX[\\/]"
    r"|(?:^|[\\/])(?:programdata|library[\\/]application support|etc)[\\/]tenetx[\\/]"
    r"|\$env:ProgramData[\\/]TenetX[\\/]|%ProgramData%[\\/]TenetX[\\/]"
    r"|[A-Za-z]:[\\/]ProgramData[\\/]TenetX[\\/]"
    r"|tenetx-guard\.py\b|tenetx-hook\.py\b"
    r"|(?:^|[\\/])tenetx[\\/]vmcp[\\/]hooks(?:[\\/]|$)",
    _gsp_re.IGNORECASE,
)
_GSP_PROTECTED_READ_RE = _gsp_re.compile(
    r"(?:^|[\\/])\.claude[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.cursor[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.codex[\\/]hooks\.json\b"
    r"|(?:^|[\\/])\.qwen[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.augment[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.vibe[\\/]hooks(?:\.toml|[\\/]|$)"
    r"|(?:^|[\\/])\.kiro[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.cline[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.clinerules[\\/]hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])Documents[\\/]Cline[\\/]Hooks(?:[\\/]|$)"
    r"|(?:^|[\\/])\.hermes[\\/](?:hooks|agent-hooks|plugins)(?:[\\/]|$)"
    r"|(?:^|[\\/])\.tenetx[\\/](?:hooks|vmcp_tokens|vmcp_keys|managed|guard|posture|attestations)(?:[\\/]|$)"
    r"|(?:^|[\\/])(?:Library[\\/]Application Support|etc|ProgramData)[\\/]TenetX[\\/]"
    r"|(?:^|[\\/])(?:programdata|library[\\/]application support|etc)[\\/]tenetx[\\/]"
    r"|\$env:ProgramData[\\/]TenetX[\\/]|%ProgramData%[\\/]TenetX[\\/]"
    r"|[A-Za-z]:[\\/]ProgramData[\\/]TenetX[\\/]"
    r"|tenetx-guard\.(?:py|sh|ps1)\b|tenetx-hook\.(?:py|sh|ps1)\b",
    _gsp_re.IGNORECASE,
)
_GSP_DIR_TOKEN_RE = _gsp_re.compile(
    r"(?:^|[\s'\"=:(,/])\.(?:codex|claude|cursor|qwen|augment|kiro|clinerules|cline|vibe)(?:[\\/]|\b)"
    r"|(?:^|[\s'\"=:(,/])\.tenetx[\\/](?:hooks|vmcp_tokens|vmcp_keys|managed|guard)",
    _gsp_re.IGNORECASE,
)
# Command substitution wrapping a literal: $(echo X) / $(printf X) -> X.
_GSP_CMDSUB_ECHO_RE = _gsp_re.compile(
    r"\$\(\s*(?:echo|printf)\s+([^)]*?)\s*\)"
)
# A write/delete TARGET only: the token after a redirection, or `dd of=`.
_GSP_REDIRECT_TARGET_RE = _gsp_re.compile(r"(?:>>?|&>|<>)\s*([^\s;&|()<>]+)")
_GSP_DD_TARGET_RE = _gsp_re.compile(r"\bof=([^\s;&|()]+)")
# tee writes its file arguments.
_GSP_TEE_RE = _gsp_re.compile(r"(?:^|[\s;&|()])tee\b((?:\s+-[A-Za-z]+)*\s+[^\s;&|()<>]+)")
# Verbs whose write/delete TARGET is the last positional argument.
_GSP_DEST_LAST_RE = _gsp_re.compile(r"(?:^|[\s;&|()])(?:mv|cp|install|ln)\b([^;&|]*)")
# Verbs that mutate ALL their positional arguments (delete / in-place / perms).
_GSP_DEST_ALL_RE = _gsp_re.compile(
    r"(?:^|[\s;&|()])(?:rm|unlink|shred|truncate|chmod|chown|chgrp)\b([^;&|]*)"
)
_GSP_PS_DEST_ALL_RE = _gsp_re.compile(
    r"(?:^|[\s;&|()])(?:Remove-Item|Clear-Content|Set-Content|Add-Content|Out-File|"
    r"Rename-Item|Move-Item|Copy-Item|New-Item|icacls|takeown|attrib|del|erase)\b([^;&|]*)",
    _gsp_re.IGNORECASE,
)
# In-place editors: target is the file arg(s) after the script.
_GSP_INPLACE_RE = _gsp_re.compile(r"(?:^|[\s;&|()])(?:sed|perl)\s+-[A-Za-z]*i[A-Za-z0-9.]*\b([^;&|]*)")
# Read/list probes of protected TenetX secret material.
_GSP_READ_ALL_RE = _gsp_re.compile(
    r"(?:^|[\s;&|()])(?:cat|head|tail|less|more|jq|yq|stat|file|ls|strings|xxd|"
    r"sha256sum|shasum|md5sum|cksum|readlink|realpath|Get-Content|gc|type|"
    r"Get-ChildItem|gci|dir)\b([^;&|]*)",
    _gsp_re.IGNORECASE,
)
_GSP_GREP_READ_RE = _gsp_re.compile(
    r"(?:^|[\s;&|()])(?:grep|egrep|fgrep|rg|ripgrep|Select-String)\b([^;&|]*)",
    _gsp_re.IGNORECASE,
)
# Interpreter that writes a file (covers paths built inside the interpreter).
_GSP_INTERP_WRITE_RE = _gsp_re.compile(
    r"\b(?:python[0-9.]*|perl|ruby|node|deno|bun|php)\b[\s\S]{0,600}"
    r"(?:\.write\(|writefile|truncate|unlink|os\.remove|os\.rename"
    r"|shutil\.(?:move|copy|copyfile)|open\([^)]{0,200}[\"'][wax])",
    _gsp_re.IGNORECASE,
)
_GSP_CHR_SEQ_RE = _gsp_re.compile(
    r"chr\(\s*(?:0[xX][0-9a-fA-F]+|\d{1,7})\s*\)"
    r"(?:\s*\+\s*chr\(\s*(?:0[xX][0-9a-fA-F]+|\d{1,7})\s*\))*"
)
_GSP_CHR_ARG_RE = _gsp_re.compile(r"chr\(\s*(0[xX][0-9a-fA-F]+|\d{1,7})\s*\)")
_GSP_HEXESC_RE = _gsp_re.compile(r"\\x([0-9a-fA-F]{2})")
_GSP_UNIESC_RE = _gsp_re.compile(r"\\u([0-9a-fA-F]{4})")
_GSP_OCTESC_RE = _gsp_re.compile(r"\\([0-3][0-7]{2}|[0-7]{1,2})")
_GSP_B64CALL_RE = _gsp_re.compile(r"b(?:ase)?64decode\(\s*[\"']([A-Za-z0-9+/=]{4,})[\"']")
_GSP_B64PIPE_RE = _gsp_re.compile(
    r"[\"']?([A-Za-z0-9+/=]{8,})[\"']?\s*\|\s*base64\s+(?:-d|-D|--decode)\b"
)
_GSP_SHELL_TOOLS = frozenset({
    "bash", "shell", "sh", "exec", "exec_command", "command_execution",
    "shell_command", "local_shell", "terminal", "run_command", "powershell",
    "query",
})
_GSP_INVARIANT_CODE = "guard_integrity"


def _gsp_local_block_message():
    return (
        "TenetX local integrity invariant blocked this action "
        "[" + _GSP_INVARIANT_CODE + "]"
    )


def _gsp_safe_chr(code):
    try:
        if 0 <= code <= 0x10FFFF:
            return chr(code)
    except (ValueError, OverflowError):
        pass
    return ""


def _gsp_try_b64(token):
    import base64 as _gsp_base64
    cand = (token or "").strip().strip("\"'")
    if len(cand) < 4 or len(cand) % 4:
        return None
    try:
        dec = _gsp_base64.b64decode(cand, validate=True).decode("utf-8")
    except Exception:
        return None
    if not dec or any(ord(ch) < 9 for ch in dec):
        return None
    return dec


def _gsp_canonicalize(command):
    text = str(command or "")[:5000]
    if not text:
        return ""

    def _chrseq(match):
        chars = []
        for arg in _GSP_CHR_ARG_RE.findall(match.group(0)):
            code = int(arg, 16) if arg.lower().startswith("0x") else int(arg)
            chars.append(_gsp_safe_chr(code))
        joined = "".join(chars)
        return (" " + joined + " ") if joined else match.group(0)

    def _b64sub(match):
        dec = _gsp_try_b64(match.group(1))
        return (" " + dec + " ") if dec else match.group(0)

    text = _GSP_CHR_SEQ_RE.sub(_chrseq, text)
    text = _GSP_HEXESC_RE.sub(lambda m: _gsp_safe_chr(int(m.group(1), 16)) or m.group(0), text)
    text = _GSP_UNIESC_RE.sub(lambda m: _gsp_safe_chr(int(m.group(1), 16)) or m.group(0), text)
    text = _GSP_OCTESC_RE.sub(lambda m: _gsp_safe_chr(int(m.group(1), 8)) or m.group(0), text)
    text = _GSP_B64CALL_RE.sub(_b64sub, text)
    text = _GSP_B64PIPE_RE.sub(_b64sub, text)
    # Unwrap $(echo X) / $(printf X) so a path assembled via command
    # substitution still resolves into the write-target position. No padding --
    # the result must stay attached to any surrounding `var=` assignment.
    for _ in range(3):
        unwrapped = _GSP_CMDSUB_ECHO_RE.sub(lambda m: m.group(1), text)
        if unwrapped == text:
            break
        text = unwrapped
    assigns = {}
    for tok in _gsp_re.split(r"[\s;&|]+", text):
        if "=" in tok and not tok.startswith(("-", "/")):
            name, _, val = tok.partition("=")
            if _gsp_re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
                assigns[name] = val.strip("'\"")
    if assigns:
        text = _gsp_re.sub(
            r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)",
            lambda m: assigns.get(m.group(1) or m.group(2), m.group(0)),
            text,
        )
    text = text.replace('"', "").replace("'", "").replace("`", "")
    return text.replace("\\", "/")


def _gsp_is_shell_tool(tool_name):
    key = str(tool_name or "").strip().lower().replace("-", "_")
    if key.startswith("mcp__"):
        return False
    return key in _GSP_SHELL_TOOLS


# A write target that looks like an agent config file (for the disable toggle).
_GSP_CONFIG_LIKE_RE = _gsp_re.compile(
    r"(?:config\.toml|config\.json|settings(?:\.local)?\.json|hooks\.json"
    r"|\.codex[\\/]|\.claude[\\/]|\.claude\.json|\.cursor[\\/]|\.qwen[\\/]"
    r"|\.augment[\\/]|\.kiro[\\/]|\.cline[\\/]|\.clinerules(?:[\\/]|\.md)"
    r"|\.vibe[\\/]"
    r"|cline_mcp_settings\.json|\.tenetx[\\/])",
    _gsp_re.IGNORECASE,
)


# --- Literal-text spans ------------------------------------------------
# A commit message that DISCUSSES a protected path is not a command that
# writes to one, but target extraction reads the whole command as a flat
# token stream and cannot tell them apart: a message containing "... rm
# <killswitch path> ..." reads as an rm of that path. Blanking the message
# span fixes that, and it has to stay narrow, because the same string is
# exactly where a real bypass would hide.
#
# Two conditions, both required:
#
#   1. The command owning the span never executes its own argument. This is
#      an allowlist, so anything unrecognized -- ``bash -c``, ``python -c``,
#      a heredoc piped to sh -- keeps full scanning.
#   2. The shell cannot expand the span into a command first. A message
#      holding a command substitution really does run it before git is
#      reached, so those spans are left alone and still scanned.
#
# Both patterns are anchored to a single command segment. Without that,
# an inert command anywhere in the line would lend its exemption to a
# sibling segment that does execute what it is handed.
_GSP_INERT_CMD = (
    r"(?:git\s+(?:commit|tag|notes)|gh\s+(?:pr|issue|release)\s+[a-z]+)"
)
_GSP_EXPANSION_RE = _gsp_re.compile(r"\$\(|\$\{|`")
_GSP_INERT_FLAG_RE = _gsp_re.compile(
    r"(?:^|[;&|])[^\n;&|]*?\b" + _GSP_INERT_CMD + r"\b[^\n;&|]*?"
    r"(?:--message|--body|--title|--notes|--description|-m|-b|-t)"
    r"(?:=|\s+)(\"[^\"]*\"|'[^']*')",
    _gsp_re.IGNORECASE,
)
# <<'EOF' and <<"EOF" suppress expansion, so the body is literal text. A
# bare <<EOF still expands and is deliberately not matched here.
_GSP_INERT_HEREDOC_RE = _gsp_re.compile(
    r"(?:^|[;&|])[^\n;&|]*?\b" + _GSP_INERT_CMD + r"\b[^\n;&|]*?"
    r"<<-?\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1[^\n;&|]*\n(.*?)\n[ \t]*\2[ \t]*$",
    _gsp_re.IGNORECASE | _gsp_re.DOTALL | _gsp_re.MULTILINE,
)


def _gsp_blank_span(match, group):
    """Blank one group, keeping every other offset in the match intact."""
    whole = match.group(0)
    payload = match.group(group)
    if not payload or _GSP_EXPANSION_RE.search(payload):
        return whole
    start = match.start(group) - match.start(0)
    end = match.end(group) - match.start(0)
    return whole[:start] + (" " * (end - start)) + whole[end:]


def _gsp_mask_inert_text(text):
    """Blank message/body spans that are literal text rather than a command.

    Applied only where TARGETS are extracted. The redirect, interpreter and
    config-toggle checks keep reading the unmasked command, so masking can
    only ever narrow what counts as a write target -- never what those
    checks are allowed to see.
    """
    masked = _GSP_INERT_HEREDOC_RE.sub(lambda m: _gsp_blank_span(m, 3), text)
    return _GSP_INERT_FLAG_RE.sub(lambda m: _gsp_blank_span(m, 1), masked)


def _gsp_write_targets(text):
    """Best-effort extraction of the WRITE/DELETE targets of a command.

    Only the paths a command actually writes, deletes, or modifies in place --
    NOT paths it merely reads, greps, or names. This keeps detection focused so
    an unrelated mutate elsewhere does not trip on an incidental mention of a
    protected path (e.g. ``grep tenetx-guard.py . > out`` or
    ``ls ~/.claude/hooks && rm /tmp/x``).
    """
    targets = []
    for m in _GSP_REDIRECT_TARGET_RE.finditer(text):
        targets.append(m.group(1))
    for m in _GSP_DD_TARGET_RE.finditer(text):
        targets.append(m.group(1))
    for m in _GSP_TEE_RE.finditer(text):
        targets.extend(t for t in m.group(1).split() if not t.startswith("-"))
    for m in _GSP_DEST_ALL_RE.finditer(text):
        targets.extend(t for t in m.group(1).split() if not t.startswith("-"))
    for m in _GSP_PS_DEST_ALL_RE.finditer(text):
        targets.extend(t for t in m.group(1).split() if not t.startswith("-"))
    for m in _GSP_INPLACE_RE.finditer(text):
        targets.extend(t for t in m.group(1).split() if not t.startswith("-"))
    for m in _GSP_DEST_LAST_RE.finditer(text):
        args = [t for t in m.group(1).split() if not t.startswith("-")]
        if args:
            targets.append(args[-1])  # mv/cp/install/ln destination is the last arg
    return targets


def _gsp_positional_args(arg_text):
    args = []
    for raw in str(arg_text or "").split():
        token = raw.strip().strip(",")
        if not token:
            continue
        if token.startswith("-") and not (token.startswith("~/") or token.startswith("/")):
            continue
        args.append(token)
    return args


def _gsp_read_targets(text):
    """Best-effort extraction of paths read/listed by shell commands."""
    targets = []
    for m in _GSP_READ_ALL_RE.finditer(text):
        targets.extend(_gsp_positional_args(m.group(1)))
    for m in _GSP_GREP_READ_RE.finditer(text):
        args = _gsp_positional_args(m.group(1))
        if len(args) >= 2:
            targets.extend(args[1:])  # first positional is usually the pattern
        elif args and (
            _GSP_PROTECTED_READ_RE.search(args[0])
            or "/" in args[0]
            or "\\" in args[0]
            or args[0].startswith(("~", "$env:", "%"))
        ):
            targets.extend(args)
    return targets


def _gsp_reason_with_scope(
    tool_name,
    tool_input,
    killswitch_re,
    protected_read_re,
    dir_token_re,
):
    if not _gsp_is_shell_tool(tool_name):
        return ""
    raw = ""
    if isinstance(tool_input, dict):
        raw = str(tool_input.get("command", "") or "")
    if not raw:
        return ""
    canon = _gsp_canonicalize(raw)
    # Canonicalization strips quotes, so literal-text spans have to be blanked
    # before it runs or the quoting that marks them is already gone.
    inert = _gsp_mask_inert_text(raw)
    canon_inert = canon if inert == raw else _gsp_canonicalize(inert)

    # 1. Relocating the agent's config root neutralizes the guard outright.
    #    Checked against the unmasked command on purpose.
    if _GSP_REDIRECT_RE.search(raw) or _GSP_REDIRECT_RE.search(canon):
        return "config_root_redirect"

    # 2. A protected path that is an actual write/delete target.
    targets = _gsp_write_targets(canon_inert) + _gsp_write_targets(
        inert.replace("\\", "/")
    )
    for target in targets:
        if killswitch_re.search(target):
            return "killswitch_path"
        if dir_token_re.search(target):
            return "governance_dir_write"

    # 2b. Reading/listing TenetX hook internals leaks enough implementation
    # detail to bypass the guard later in the same session.
    read_targets = _gsp_read_targets(canon_inert) + _gsp_read_targets(
        inert.replace("\\", "/")
    )
    for target in read_targets:
        if protected_read_re.search(target):
            return "guard_read_probe"

    # 3. Interpreter writing a file whose path is assembled in-process. The
    #    interpreter call is self-contained, so a write op together with a
    #    protected path/token in the same command is the tamper signal.
    if _GSP_INTERP_WRITE_RE.search(raw) and (
        killswitch_re.search(canon) or dir_token_re.search(canon)
    ):
        return "killswitch_path"

    # 4. Writing the hook-disable flag into a config-like target.
    if _GSP_HOOK_DISABLE_RE.search(canon) and any(
        _GSP_CONFIG_LIKE_RE.search(t) for t in targets
    ):
        return "hook_disable_toggle"
    if (
        _GSP_INTERP_WRITE_RE.search(raw)
        and _GSP_HOOK_DISABLE_RE.search(canon)
        and _GSP_CONFIG_LIKE_RE.search(canon)
    ):
        return "hook_disable_toggle"

    return ""


def _gsp_self_protection_reason(tool_name, tool_input):
    """Broad server-side governance classification."""
    return _gsp_reason_with_scope(
        tool_name,
        tool_input,
        _GSP_KILLSWITCH_RE,
        _GSP_PROTECTED_READ_RE,
        _GSP_DIR_TOKEN_RE,
    )


def _gsp_local_integrity_reason(tool_name, tool_input):
    """Narrow non-overridable detector embedded into endpoint guards."""
    return _gsp_reason_with_scope(
        tool_name,
        tool_input,
        _GSP_LOCAL_KILLSWITCH_RE,
        _GSP_LOCAL_PROTECTED_READ_RE,
        _GSP_LOCAL_DIR_TOKEN_RE,
    )




def should_fail_open(tool_name, tool_input):
    # Configured fail-open never bypasses the emergency high-risk floor.
    if is_high_risk(tool_name, tool_input):
        return False
    if FAIL_MODE == "closed":
        return False
    if FAIL_MODE == "open":
        return True

    normalized_tool = normalize_tool_name(tool_name)
    if LOCAL_FAILSAFE and normalized_tool in ("Write", "Edit"):
        return False
    return not is_high_risk(normalized_tool, tool_input)


def validate_policy_response(result):
    if not isinstance(result, dict) or result.get("decision") not in ("allow", "ask", "block"):
        raise ValueError("invalid_policy_response")
    return result


def normalize_tool_name(tool_name):
    text = str(tool_name or "").strip()
    key = text.lower().replace("-", "_")
    if parse_native_mcp_tool_name(text):
        return "MCP"
    shell_names = {
        "bash",
        "shell",
        "sh",
        "exec_command",
        "command_execution",
        "shell_command",
        "local_shell",
        "terminal",
        "run_command",
    }
    if key in shell_names:
        return "Bash"
    if key == "exec":
        # Generic Codex exec is a JavaScript carrier. The server dissects it
        # before assigning semantics; never parse the outer text as shell.
        return "CodexExec"
    return {
        "read": "Read",
        "read_file": "Read",
        "write": "Write",
        "write_file": "Write",
        "edit": "Edit",
        "apply_patch": "Edit",
        "query": "Bash",
        "mcp": "MCP",
        "mcp_tool": "MCP",
        "browser": "Browser",
        "browser_action": "Browser",
        "browser_navigate": "Browser",
        "browser_type": "Browser",
        "browser_click": "Browser",
        "browser_upload": "Browser",
        "browser_download": "Browser",
        "browser_eval": "Browser",
        "javascript_eval": "Browser",
    }.get(key, text)


def normalize_tool_input(tool_name, tool_input, raw_tool_name=None):
    if not isinstance(tool_input, dict):
        return {}
    data = dict(tool_input)
    raw_name = raw_tool_name or data.get("raw_tool_name") or tool_name
    normalized_tool_name = normalize_tool_name(tool_name)
    if normalized_tool_name != tool_name:
        tool_name = normalized_tool_name
    data.setdefault("raw_tool_name", raw_name)
    if tool_name == "Bash":
        command = data.get("command")
        if isinstance(command, list):
            data["command"] = " ".join(shlex.quote(str(part)) for part in command)
        elif not isinstance(command, str) or not command.strip():
            for key in ("cmd", "shell_command", "raw_command", "display_command", "sql"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    data["command"] = value
                    break
            else:
                for key in ("argv", "args"):
                    value = data.get(key)
                    if isinstance(value, list) and value:
                        data["command"] = " ".join(shlex.quote(str(part)) for part in value)
                        break
    elif tool_name == "MCP":
        mcp_parts = parse_native_mcp_tool_name(raw_name, data)
        for key, value in mcp_parts.items():
            data.setdefault(key, value)
        invocation = data.get("invocation") if isinstance(data.get("invocation"), dict) else {}
        arguments = data.get("arguments")
        if not isinstance(arguments, dict):
            arguments = invocation.get("arguments")
            if isinstance(arguments, dict):
                data["arguments"] = arguments
        if isinstance(arguments, dict):
            data.setdefault("raw_params", arguments)
            for key, value in arguments.items():
                data.setdefault(key, value)
    elif tool_name in ("Read", "Write", "Edit"):
        for key in ("path", "target_path"):
            value = data.get(key)
            if not data.get("file_path") and isinstance(value, str) and value.strip():
                data["file_path"] = value
                break
        patch_text = data.get("patch") or data.get("command") or data.get("input")
        patch_data = extract_patch_targets(patch_text)
        if patch_data:
            for key, value in patch_data.items():
                data.setdefault(key, value)
            if not data.get("file_path"):
                data["file_path"] = patch_data["target_paths"][0]
    return data


def debug_log(message):
    if not DEBUG_ENABLED:
        return
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(timestamp + " " + message + "\n")
    except Exception:
        pass


def _log_value(value, max_len=120):
    text = str(value if value is not None else "")
    text = re.sub(r"[^A-Za-z0-9_.:@/=-]+", "_", text).strip("_")
    return text[:max_len]


def rca_log(event, **fields):
    """Always-on local telemetry for Codex ASK feedback delivery.

    Keep this deliberately narrow: no command text, prompt text, tool input,
    user email, tokens, or exception messages. The goal is to prove the local
    bridge saw a native approval result and whether the backend accepted it.
    """
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        parts = [
            "rca_event=" + _log_value(event),
            "org=" + _log_value(TENETX_ORG),
            "surface=" + _log_value(CLIENT_SURFACE),
        ]
        for key in sorted(fields):
            value = fields.get(key)
            if value is None:
                continue
            parts.append(_log_value(key, 50) + "=" + _log_value(value))
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(timestamp + " " + " ".join(parts) + "\n")
    except Exception:
        pass


def _expand_posture_path(raw_path):
    expanded = raw_path.replace("$HOME", os.path.expanduser("~"))
    expanded = os.path.expandvars(expanded)
    return os.path.abspath(os.path.expanduser(expanded))


def _atomic_write_text(path, content, mode=0o644):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=os.path.basename(path) + ".", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def write_posture_marker(status, reason, api_path=""):
    normalized = POSTURE_HEALTHY_VALUE if status == POSTURE_HEALTHY_VALUE else POSTURE_UNHEALTHY_VALUE
    now = int(time.time())
    expires_at = now + max(POSTURE_TTL_SECONDS, 30) if normalized == POSTURE_HEALTHY_VALUE else now
    details = {
        "schema": "tenetx.ai/zscaler-ai-hook-posture/v1",
        "status": normalized,
        "org_slug": TENETX_ORG,
        "hook_type": "codex",
        "client_surface": CLIENT_SURFACE,
        "reason": reason,
        "api_path": api_path,
        "last_evaluated_at_epoch": now,
        "expires_at_epoch": expires_at,
        "agent_health": {
            "codex": {
                "status": normalized,
                "last_verified_at_epoch": now if normalized == POSTURE_HEALTHY_VALUE else None,
            }
        },
    }
    try:
        _atomic_write_text(_expand_posture_path(POSTURE_MARKER_PATH), normalized + "\n")
        _atomic_write_text(
            _expand_posture_path(POSTURE_DETAILS_PATH),
            json.dumps(details, indent=2, sort_keys=True) + "\n",
        )
        healthy_sentinel = _expand_posture_path(POSTURE_HEALTHY_SENTINEL_PATH)
        if normalized == POSTURE_HEALTHY_VALUE:
            _atomic_write_text(healthy_sentinel, POSTURE_HEALTHY_VALUE + "\n")
        elif os.path.exists(healthy_sentinel):
            os.unlink(healthy_sentinel)
    except Exception as exc:
        debug_log("posture_marker_error=" + type(exc).__name__ + " " + str(exc)[:120])


def posture_evidence():
    marker = _expand_posture_path(POSTURE_MARKER_PATH)
    details_path = _expand_posture_path(POSTURE_DETAILS_PATH)
    healthy_sentinel = _expand_posture_path(POSTURE_HEALTHY_SENTINEL_PATH)
    evidence = {
        "schema": "tenetx.ai/zscaler-ai-hook-posture-evidence/v1",
        "source": "hook_runtime",
        "status": "unknown",
        "fresh": False,
        "reason": "posture_details_missing",
        "marker_path": marker,
        "details_path": details_path,
        "healthy_sentinel_path": healthy_sentinel,
        "healthy_sentinel_exists": os.path.exists(healthy_sentinel),
    }
    try:
        if os.path.exists(marker):
            with open(marker, "r", encoding="utf-8") as handle:
                evidence["marker_value"] = handle.read().strip()[:64]
    except Exception as exc:
        evidence["marker_read_error"] = type(exc).__name__
    try:
        with open(details_path, "r", encoding="utf-8") as handle:
            details = json.load(handle)
        if isinstance(details, dict):
            for key in (
                "status",
                "reason",
                "api_path",
                "last_evaluated_at_epoch",
                "expires_at_epoch",
                "hook_type",
                "client_surface",
            ):
                if key in details:
                    evidence[key] = details.get(key)
            expires_at = details.get("expires_at_epoch")
            status = details.get("status")
            evidence["fresh"] = (
                status == POSTURE_HEALTHY_VALUE
                and isinstance(expires_at, (int, float))
                and expires_at > int(time.time())
            )
    except FileNotFoundError:
        pass
    except Exception as exc:
        evidence["reason"] = "posture_evidence_error:" + type(exc).__name__
    return evidence


def _pending_ask_dir():
    return os.path.expanduser("~/.tenetx/state/codex_pending_asks")


def _native_rejection_dir():
    return os.path.expanduser("~/.tenetx/state/codex_native_rejections")


def _pending_ask_key(tool_call_id, session_id, tool_name):
    raw = "|".join(str(value or "") for value in (TENETX_ORG, tool_call_id, session_id, tool_name))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _native_rejection_key(tool_call_id, session_id):
    raw = "|".join(str(value or "") for value in (TENETX_ORG, tool_call_id, session_id))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _pending_ask_path(tool_call_id, session_id, tool_name):
    return os.path.join(_pending_ask_dir(), _pending_ask_key(tool_call_id, session_id, tool_name) + ".json")


def _prompt_work_item_ask_path(session_id):
    raw = "|".join(str(value or "") for value in (TENETX_ORG, session_id, "UserPromptSubmit", "work_item_required"))
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return os.path.join(_pending_ask_dir(), "work-item-" + digest + ".json")


def _native_rejection_path(tool_call_id, session_id):
    return os.path.join(_native_rejection_dir(), _native_rejection_key(tool_call_id, session_id) + ".json")


def _safe_unlink(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except Exception as exc:
        debug_log("pending_ask_unlink_error=" + type(exc).__name__)


def _write_json_atomic(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
        os.replace(tmp_path, path)
    except Exception:
        _safe_unlink(tmp_path)
        raise


def remember_pending_ask(hook_input, tool_name, session_id, vmcp_correlation_id, result):
    """Persist minimal local state so a later Codex Skip can become feedback."""
    if not vmcp_correlation_id:
        debug_log("pending_ask_skip_no_tool_call_id")
        return
    raw_tool_input = hook_input.get("tool_input") if isinstance(hook_input, dict) else None
    record = {
        "version": 1,
        "org": TENETX_ORG,
        "created_at": time.time(),
        "session_id": session_id,
        "turn_id": hook_input.get("turn_id") or "",
        "tool_call_id": vmcp_correlation_id,
        "tool_name": tool_name,
        "agent_id": socket.gethostname(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "user_email": os.environ.get("TENETX_USER_EMAIL", ""),
    }
    if isinstance(raw_tool_input, dict):
        record["tool_input"] = normalize_tool_input(tool_name, raw_tool_input, raw_tool_input.get("raw_tool_name"))
    if isinstance(result, dict):
        for key in ("decision_id", "policy_decision_id"):
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                record["decision_id"] = value.strip()
                break
    try:
        _write_json_atomic(_pending_ask_path(vmcp_correlation_id, session_id, tool_name), record)
        debug_log("pending_ask_recorded tool_call_id=" + str(vmcp_correlation_id))
    except Exception as exc:
        debug_log("pending_ask_record_error=" + type(exc).__name__ + " " + str(exc)[:120])
        _record_capture_failure("codex", "/approval-correlation", exc, hook_input)


def _is_work_item_required_result(result):
    if not isinstance(result, dict):
        return False
    codes = []
    for key in ("reason_code", "code"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            codes.append(value.strip())
    reason_codes = result.get("reason_codes")
    if isinstance(reason_codes, list):
        codes.extend(str(value or "").strip() for value in reason_codes)
    workflow = result.get("workflow")
    if isinstance(workflow, dict):
        for key in ("reason_code", "code"):
            value = workflow.get(key)
            if isinstance(value, str) and value.strip():
                codes.append(value.strip())
    return any(
        str(code).upper()
        in {
            "DEVWORKFLOW.WORK_ITEM_REQUIRED",
            "DEVWORKFLOW.WORK_ITEM_CONFIRMATION_REQUIRED",
            "DEVWORKFLOW.WORK_ITEM_INVALID",
        }
        for code in codes
    )


def remember_prompt_work_item_ask(session_id, result):
    """Persist session-scoped work-item intake state for the next prompt."""
    if not session_id:
        debug_log("prompt_work_item_ask_skip_no_session")
        return
    record = {
        "version": 1,
        "kind": "prompt_work_item_required",
        "org": TENETX_ORG,
        "created_at": time.time(),
        "session_id": session_id,
        "tool_name": "UserPromptSubmit",
        "agent_id": socket.gethostname(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "user_email": os.environ.get("TENETX_USER_EMAIL", ""),
    }
    if isinstance(result, dict):
        for key in ("decision_id", "policy_decision_id"):
            value = result.get(key)
            if isinstance(value, str) and value.strip():
                record["decision_id"] = value.strip()
                break
        if isinstance(result.get("reason_code"), str):
            record["reason_code"] = result.get("reason_code")
    try:
        _write_json_atomic(_prompt_work_item_ask_path(session_id), record)
        rca_log("codex_prompt_work_item_ask_recorded", session_id=session_id)
    except Exception as exc:
        debug_log("prompt_work_item_ask_record_error=" + type(exc).__name__ + " " + str(exc)[:120])


def load_prompt_work_item_ask(session_id):
    if not session_id:
        return None
    path = _prompt_work_item_ask_path(session_id)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            record = json.load(handle)
    except Exception:
        return None
    if not isinstance(record, dict) or record.get("org") != TENETX_ORG:
        return None
    created_at = float(record.get("created_at") or 0)
    if created_at and time.time() - created_at > PENDING_ASK_TTL_SECONDS:
        _safe_unlink(path)
        return None
    record["_path"] = path
    return record


def forget_prompt_work_item_ask(session_id):
    if not session_id:
        return
    _safe_unlink(_prompt_work_item_ask_path(session_id))


def forget_pending_ask(tool_call_id, session_id, tool_name):
    if not tool_call_id:
        return
    _safe_unlink(_pending_ask_path(tool_call_id, session_id, tool_name))


def load_pending_ask(tool_call_id, session_id, tool_name):
    if not tool_call_id:
        return None
    path = _pending_ask_path(tool_call_id, session_id, tool_name)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            record = json.load(handle)
    except Exception:
        return None
    return record if isinstance(record, dict) and record.get("org") == TENETX_ORG else None


def _iter_pending_asks(session_id=None):
    directory = _pending_ask_dir()
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return
    except Exception as exc:
        debug_log("pending_ask_list_error=" + type(exc).__name__)
        return

    now = time.time()
    for name in names:
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                record = json.load(handle)
        except Exception:
            _safe_unlink(path)
            continue
        if not isinstance(record, dict):
            _safe_unlink(path)
            continue
        if record.get("org") != TENETX_ORG:
            continue
        created_at = float(record.get("created_at") or 0)
        if created_at and now - created_at > PENDING_ASK_TTL_SECONDS:
            debug_log("pending_ask_expired tool_call_id=" + str(record.get("tool_call_id") or ""))
            _safe_unlink(path)
            continue
        if session_id and record.get("session_id") and record.get("session_id") != session_id:
            continue
        record["_path"] = path
        yield record


def _codex_home():
    """Codex data dir for rollout discovery: honor CODEX_HOME (the Codex CLI's
    own override for where sessions/rollouts live), else ~/.codex."""
    override = os.environ.get("CODEX_HOME")
    if override:
        return os.path.expanduser(override)
    return os.path.expanduser("~/.codex")


def _codex_session_files(session_id):
    root = os.path.join(_codex_home(), "sessions")
    if not session_id:
        return []
    matches = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in ("node_modules", ".git")]
            for filename in filenames:
                if filename.endswith(".jsonl") and session_id in filename:
                    path = os.path.join(dirpath, filename)
                    try:
                        matches.append((os.path.getmtime(path), path))
                    except OSError:
                        pass
    except Exception as exc:
        debug_log("codex_session_walk_error=" + type(exc).__name__)
        return []
    matches.sort(reverse=True)
    return [path for _, path in matches[:5]]


def _read_file_tail(path, max_bytes):
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes), os.SEEK_SET)
            return handle.read().decode("utf-8", errors="replace")
    except Exception as exc:
        debug_log("codex_session_tail_error=" + type(exc).__name__)
        return ""


def _latest_codex_turn_context(session_id):
    """Return runtime posture from the newest real Codex turn context.

    Current Codex hook payloads do not consistently include model or
    permission_mode. The rollout is authoritative for both: each turn_context
    records ``model`` and ``sandbox_policy.type``.
    """
    for path in _codex_session_files(session_id):
        lines = _read_file_tail(path, CODEX_SESSION_SCAN_BYTES).splitlines()
        for line in reversed(lines):
            try:
                item = json.loads(line)
            except Exception:
                continue
            if not isinstance(item, dict) or item.get("type") != "turn_context":
                continue
            payload = item.get("payload")
            if not isinstance(payload, dict):
                continue
            sandbox_policy = payload.get("sandbox_policy")
            permission_mode = ""
            if isinstance(sandbox_policy, dict):
                permission_mode = str(sandbox_policy.get("type") or "").strip()
            if not permission_mode:
                permission_mode = str(payload.get("permission_mode") or "").strip()
            return {
                "model": str(payload.get("model") or "").strip(),
                "permission_mode": permission_mode,
            }
    return {}


def _enrich_codex_runtime_context(hook_input, session_id):
    if not isinstance(hook_input, dict):
        return hook_input
    if hook_input.get("model") and hook_input.get("permission_mode"):
        return hook_input
    context = _latest_codex_turn_context(session_id)
    if not context:
        return hook_input
    enriched = dict(hook_input)
    for key in ("model", "permission_mode"):
        if not enriched.get(key) and context.get(key):
            enriched[key] = context[key]
    return enriched


def _codex_output_text(output):
    if isinstance(output, str):
        return output
    if isinstance(output, list):
        parts = []
        for item in output:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("output")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    if isinstance(output, dict):
        text = output.get("text") or output.get("output")
        return text if isinstance(text, str) else ""
    return ""


def _is_codex_user_rejection_output(output):
    text = _codex_output_text(output).lower()
    return "rejected by user" in text or "aborted by user" in text


def _codex_custom_call_arguments(payload):
    value = payload.get("input") if isinstance(payload, dict) else None
    if isinstance(value, dict):
        return dict(value)
    if not isinstance(value, str):
        return {}
    marker = "tools.exec_command"
    marker_index = value.find(marker)
    if marker_index < 0:
        return {}
    object_index = value.find("{", marker_index + len(marker))
    if object_index < 0:
        return {}
    try:
        parsed, _ = json.JSONDecoder().raw_decode(value[object_index:])
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        # Codex 0.146.0 serializes real custom exec calls as JavaScript source,
        # not JSON: ``tools.exec_command({cmd:"...", workdir:"..."})``.
        # Parse only the string fields needed for policy correlation; never
        # evaluate the JavaScript payload.
        parsed = {}
        object_text = value[object_index:]
        for key in ("cmd", "command", "shell_command", "raw_command", "workdir"):
            match = re.search(
                r"(?:^|[,{}])\s*(?:\"" + re.escape(key) + r"\"|" + re.escape(key)
                + r")\s*:\s*",
                object_text,
            )
            if not match:
                continue
            try:
                field_value, _ = json.JSONDecoder().raw_decode(object_text[match.end():])
            except Exception as parse_error:
                _record_capture_failure(
                    "codex",
                    "/custom-call-arguments/" + key,
                    parse_error,
                    {"input": value},
                )
                continue
            if isinstance(field_value, str):
                parsed[key] = field_value
        return parsed


def _tool_from_codex_custom_call(call_payload, output):
    raw_tool_name = str(call_payload.get("name") or "unknown")
    args = _codex_custom_call_arguments(call_payload)
    # `_codex_custom_call_arguments` only succeeds after proving the carrier
    # contains a literal tools.exec_command({...}) call. Preserve the outer
    # carrier as provenance while correlating the already-decoded inner action
    # as Bash for pending-ASK and native-rejection lifecycle handling.
    decoded_tool_name = "exec_command" if raw_tool_name.lower() == "exec" and args else raw_tool_name
    tool_name, tool_input = _tool_from_codex_function_call(
        {"name": decoded_tool_name, "arguments": args},
        _codex_output_text(output),
    )
    if decoded_tool_name != raw_tool_name:
        tool_input["outer_tool_name"] = raw_tool_name
    return tool_name, tool_input


def _codex_session_has_user_rejection(record):
    tool_call_id = str(record.get("tool_call_id") or "").strip()
    session_id = str(record.get("session_id") or "").strip()
    if not tool_call_id or not session_id:
        return False
    expected_input = record.get("tool_input") if isinstance(record.get("tool_input"), dict) else {}
    expected_command = str(expected_input.get("command") or "").strip()
    created_at = float(record.get("created_at") or 0)
    for path in _codex_session_files(session_id):
        tail = _read_file_tail(path, CODEX_SESSION_SCAN_BYTES)
        calls = {}
        for line in tail.splitlines():
            try:
                item = json.loads(line)
            except Exception:
                continue
            payload = item.get("payload") if isinstance(item, dict) else None
            if not isinstance(payload, dict):
                continue
            payload_type = payload.get("type")
            call_id = str(payload.get("call_id") or "").strip()
            if not call_id:
                continue
            if payload_type in ("function_call", "custom_tool_call"):
                calls[call_id] = payload
                continue
            if payload_type not in ("function_call_output", "custom_tool_call_output"):
                continue
            if not _is_codex_user_rejection_output(payload.get("output")):
                continue
            if call_id == tool_call_id:
                record["_native_call_id"] = call_id
                return True
            event_ts = _parse_codex_timestamp(item.get("timestamp"))
            if created_at and event_ts and event_ts < created_at - 10:
                continue
            call_payload = calls.get(call_id) or {}
            if payload_type == "custom_tool_call_output":
                _, tool_input = _tool_from_codex_custom_call(call_payload, payload.get("output"))
            else:
                _, tool_input = _tool_from_codex_function_call(call_payload, payload.get("output"))
            actual_command = str(tool_input.get("command") or "").strip()
            if expected_command and actual_command == expected_command:
                record["_native_call_id"] = call_id
                return True
    return False


def _parse_codex_timestamp(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        text = value.strip().replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


def _parse_json_maybe(value):
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _command_from_rejection_output(output):
    if not isinstance(output, str):
        return ""
    match = re.search(r"failed for `(.+?)`:", output)
    return match.group(1).strip() if match else ""


def _tool_from_codex_function_call(call_payload, output):
    raw_tool_name = str(call_payload.get("name") or "unknown")
    args = _parse_json_maybe(call_payload.get("arguments"))
    tool_name = normalize_tool_name(raw_tool_name)

    if tool_name == "Bash":
        tool_input = {
            "command": (
                args.get("cmd")
                or args.get("command")
                or args.get("shell_command")
                or args.get("raw_command")
                or _command_from_rejection_output(output)
            )
        }
        if args.get("workdir"):
            tool_input["cwd"] = args.get("workdir")
    elif tool_name == "Edit":
        tool_input = {
            "patch": args.get("patch") or args.get("command") or args.get("input") or "",
            "file_path": args.get("file_path") or args.get("path") or "",
        }
    else:
        tool_input = dict(args)

    tool_input["raw_tool_name"] = raw_tool_name
    return tool_name, normalize_tool_input(tool_name, tool_input, raw_tool_name)


def _native_rejection_already_sent(tool_call_id, session_id):
    if not tool_call_id:
        return True
    return os.path.exists(_native_rejection_path(tool_call_id, session_id))


def _mark_native_rejection_sent(record, result):
    tool_call_id = record.get("tool_call_id")
    if not tool_call_id:
        return
    payload = {
        "version": 1,
        "org": TENETX_ORG,
        "created_at": time.time(),
        "session_id": record.get("session_id") or "",
        "tool_call_id": tool_call_id,
        "decision_id": (result or {}).get("decision_id") if isinstance(result, dict) else None,
    }
    try:
        _write_json_atomic(_native_rejection_path(tool_call_id, record.get("session_id") or ""), payload)
        rca_log(
            "codex_native_rejection_marker_written",
            tool_call_id=tool_call_id,
            session_id=record.get("session_id") or "",
            decision_id=payload.get("decision_id") or "",
        )
    except Exception as exc:
        debug_log("native_rejection_mark_error=" + type(exc).__name__)
        rca_log(
            "codex_native_rejection_marker_error",
            tool_call_id=tool_call_id,
            session_id=record.get("session_id") or "",
            error_type=type(exc).__name__,
        )


def _iter_codex_native_rejections(session_id=None, since_ts=None):
    calls = {}
    for path in _codex_session_files(session_id):
        tail = _read_file_tail(path, CODEX_SESSION_SCAN_BYTES)
        for line in tail.splitlines():
            try:
                item = json.loads(line)
            except Exception:
                continue
            payload = item.get("payload") if isinstance(item, dict) else None
            if not isinstance(payload, dict):
                continue
            payload_type = payload.get("type")
            call_id = str(payload.get("call_id") or "").strip()
            if not call_id:
                continue
            if payload_type in ("function_call", "custom_tool_call"):
                calls[call_id] = payload
                continue
            if payload_type not in ("function_call_output", "custom_tool_call_output"):
                continue
            output = payload.get("output")
            if not _is_codex_user_rejection_output(output):
                continue
            event_ts = _parse_codex_timestamp(item.get("timestamp"))
            if since_ts and event_ts and event_ts < since_ts:
                continue
            if _native_rejection_already_sent(call_id, session_id or ""):
                continue
            call_payload = calls.get(call_id) or {}
            if payload_type == "custom_tool_call_output":
                tool_name, tool_input = _tool_from_codex_custom_call(call_payload, output)
            else:
                tool_name, tool_input = _tool_from_codex_function_call(call_payload, output)
            yield {
                "session_id": session_id or "",
                "tool_call_id": call_id,
                "tool_name": tool_name,
                "tool_input": tool_input,
                "output": output,
                "event_timestamp": item.get("timestamp"),
            }


def send_codex_check(hook_input, tool_name, tool_input, session_id, vmcp_correlation_id, hook_event_name="PermissionRequest"):
    payload = {
        "client_surface": CLIENT_SURFACE,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "hook_event_name": hook_event_name,
        "tool_call_id": vmcp_correlation_id,
        "tool_use_id": vmcp_correlation_id,
        "request_id": vmcp_correlation_id,
        "id": vmcp_correlation_id,
        "trace_id": vmcp_correlation_id,
        "session_id": session_id,
        "prompt_session_id": session_id,
        "agent_id": socket.gethostname(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "user_email": os.environ.get("TENETX_USER_EMAIL", ""),
        "hook_type": "request",
        "metadata": {
            "model": hook_input.get("model", "") if isinstance(hook_input, dict) else "",
            "turn_id": hook_input.get("turn_id", "") if isinstance(hook_input, dict) else "",
            "permission_mode": hook_input.get("permission_mode", "") if isinstance(hook_input, dict) else "",
            "cwd": hook_input.get("cwd", "") if isinstance(hook_input, dict) else "",
            "hook_event_name": hook_event_name,
            "raw_tool_name": tool_input.get("raw_tool_name", "") if isinstance(tool_input, dict) else "",
            "approval_description": hook_input.get("description", "") if isinstance(hook_input, dict) else "",
        },
    }

    _merge_skill_inventory(payload, session_id=session_id)

    url = TENETX_URL + "/api/vmcp/" + TENETX_ORG + "/codex/check"
    try:
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if VMCP_TOKEN:
            headers["Authorization"] = "Bearer " + VMCP_TOKEN
        req = urllib.request.Request(
            url,
            data=_json_payload(payload, urlparse(url).path),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT) as response:
            result = json.load(response)
        result = validate_policy_response(result)
        debug_log("codex_check_ok")
        write_posture_marker(POSTURE_HEALTHY_VALUE, "tenetx_api_verified", "/codex/check")
        return result
    except Exception as exc:
        debug_log("codex_check_error=" + type(exc).__name__ + " " + str(exc)[:160])
        write_posture_marker(POSTURE_UNHEALTHY_VALUE, "tenetx_api_error:" + type(exc).__name__, "/codex/check")
        return None


def _extract_work_item_key_reply(prompt):
    if not isinstance(prompt, str):
        return ""
    match = WORK_ITEM_KEY_RE.search(prompt)
    return match.group(1).upper() if match else ""


def _prompt_requests_regular_work(prompt):
    if not isinstance(prompt, str):
        return False
    text = prompt.strip().lower()
    if not text:
        return False
    compact = re.sub(r"[^a-z0-9]+", " ", text).strip()
    exact = {
        "regular",
        "regular work",
        "no ticket",
        "no jira",
        "no jira id",
        "no jira issue",
        "no jira ticket",
        "no issue",
        "no issue id",
        "no work item",
        "skip",
        "skip ticket",
        "skip jira",
        "skip work item",
    }
    if compact in exact:
        return True
    patterns = (
        r"\b(?:this is|mark as|set as|treat as)\s+regular(?:\s+work)?\b",
        r"\b(?:continue|proceed|go ahead|carry on)\b.{0,80}\bwithout\b.{0,80}\b(?:jira|ticket|work item|issue|one)\b",
        r"\b(?:i|we)\s+(?:do not|don't|dont)\s+have\s+(?:a\s+)?(?:jira|ticket|work item|issue)\b",
        r"\b(?:no|without)\s+(?:jira|ticket|work item|issue)\b",
        r"\bskip\s+(?:the\s+)?(?:jira|ticket|work item|issue)\b",
    )
    return any(re.search(pattern, text) for pattern in patterns)


def _work_item_reply_tool_input(prompt):
    key = _extract_work_item_key_reply(prompt)
    if key:
        return {
            "prompt": "TenetX workflow work item: " + key,
            "work_item_key": key,
            "_tenetx_ask_mcp": True,
        }
    if _prompt_requests_regular_work(prompt):
        return {
            "prompt": "TenetX workflow regular work without Jira issue.",
            "work_item_mode": "regular",
            "work_item_skip": True,
            "work_item_skip_reason": "Developer selected regular work in Codex after TenetX work-item prompt.",
            "_tenetx_ask_mcp": True,
        }
    return None


def _handle_prompt_work_item_reply(hook_input, session_id, prompt, vmcp_correlation_id):
    pending = load_prompt_work_item_ask(session_id)
    if not pending:
        return None
    tool_input = _work_item_reply_tool_input(prompt)
    if not tool_input:
        return None
    result = send_codex_check(
        hook_input,
        "UserPromptSubmit",
        tool_input,
        session_id,
        vmcp_correlation_id,
        hook_event_name="UserPromptSubmit",
    )
    if not isinstance(result, dict):
        return None
    decision = str(result.get("decision") or "allow").lower()
    if decision == "allow":
        forget_prompt_work_item_ask(session_id)
        rca_log(
            "codex_prompt_work_item_reply_allowed",
            session_id=session_id,
            work_item_key=tool_input.get("work_item_key") or "",
            work_item_mode=tool_input.get("work_item_mode") or "",
        )
    elif _is_work_item_required_result(result):
        remember_prompt_work_item_ask(session_id, result)
    return result


def flush_native_codex_rejection_feedback(session_id=None, since_ts=None):
    """Persist and resolve Codex native prompt denials that never invoke hooks."""
    for record in list(_iter_codex_native_rejections(session_id=session_id, since_ts=since_ts)):
        rca_log(
            "codex_native_rejection_detected",
            tool_call_id=record.get("tool_call_id") or "",
            session_id=record.get("session_id") or "",
            tool_name=record.get("tool_name") or "unknown",
        )
        result = send_codex_check(
            {
                "hook_event_name": "PermissionRequest",
                "session_id": record.get("session_id") or "",
                "tool_call_id": record.get("tool_call_id"),
            },
            record.get("tool_name") or "unknown",
            record.get("tool_input") or {},
            record.get("session_id") or "",
            record.get("tool_call_id"),
            hook_event_name="PermissionRequest",
        )
        if result is None:
            rca_log(
                "codex_native_rejection_check_error",
                tool_call_id=record.get("tool_call_id") or "",
                session_id=record.get("session_id") or "",
            )
            continue
        check_decision_id = result.get("decision_id") or result.get("policy_decision_id") or ""
        if result.get("decision") == "ask":
            rca_log(
                "codex_native_rejection_check_ask",
                tool_call_id=record.get("tool_call_id") or "",
                session_id=record.get("session_id") or "",
                decision_id=check_decision_id,
            )
            feedback_result = send_decision_feedback(
                {
                    "decision_id": check_decision_id,
                    "policy_decision_id": check_decision_id,
                },
                record.get("tool_name") or "unknown",
                record.get("session_id") or "",
                record.get("tool_call_id"),
                status="denied_by_user",
                reason="codex_native_permission_rejected",
                tool_input=record.get("tool_input") or {},
            )
            if feedback_result is None:
                rca_log(
                    "codex_native_rejection_feedback_error",
                    tool_call_id=record.get("tool_call_id") or "",
                    session_id=record.get("session_id") or "",
                    decision_id=check_decision_id,
                    status="denied_by_user",
                )
                continue
            debug_log("native_rejection_feedback_sent tool_call_id=" + str(record.get("tool_call_id") or ""))
            rca_log(
                "codex_native_rejection_feedback_sent",
                tool_call_id=record.get("tool_call_id") or "",
                session_id=record.get("session_id") or "",
                decision_id=(feedback_result or {}).get("decision_id") or check_decision_id,
                status="denied_by_user",
                resolved=(feedback_result or {}).get("resolved"),
            )
            _mark_native_rejection_sent(record, feedback_result)
            continue
        debug_log(
            "native_rejection_check_not_ask tool_call_id="
            + str(record.get("tool_call_id") or "")
            + " decision="
            + str(result.get("decision") or "")
        )
        rca_log(
            "codex_native_rejection_check_not_ask",
            tool_call_id=record.get("tool_call_id") or "",
            session_id=record.get("session_id") or "",
            decision=result.get("decision") or "",
            decision_id=check_decision_id,
        )
        _mark_native_rejection_sent(record, result)


def flush_pending_codex_skip_feedback(session_id=None):
    """Bridge Codex native Skip into TenetX denied_by_user feedback."""
    for record in list(_iter_pending_asks(session_id)):
        if not _codex_session_has_user_rejection(record):
            continue
        result = send_decision_feedback(
            {
                "decision_id": record.get("decision_id"),
                "policy_decision_id": record.get("decision_id"),
            },
            record.get("tool_name") or "unknown",
            record.get("session_id") or "",
            record.get("tool_call_id"),
            status="denied_by_user",
            reason="codex_native_permission_skipped",
            tool_input=record.get("tool_input") or {},
        )
        if result is not None:
            debug_log("pending_ask_denied_feedback_sent tool_call_id=" + str(record.get("tool_call_id") or ""))
            rca_log(
                "codex_pending_ask_denied_feedback_sent",
                tool_call_id=record.get("tool_call_id") or "",
                session_id=record.get("session_id") or "",
                decision_id=(result or {}).get("decision_id") or record.get("decision_id") or "",
                status="denied_by_user",
                resolved=(result or {}).get("resolved"),
            )
            _mark_native_rejection_sent(record, result)
            native_call_id = str(record.get("_native_call_id") or "").strip()
            if native_call_id and native_call_id != record.get("tool_call_id"):
                native_record = dict(record)
                native_record["tool_call_id"] = native_call_id
                _mark_native_rejection_sent(native_record, result)
            _safe_unlink(record.get("_path") or "")


def _start_skip_feedback_watcher(session_id):
    if SKIP_WATCHER_DISABLED:
        return
    script_path = globals().get("__file__")
    if not script_path or script_path == "<string>":
        return
    try:
        env = os.environ.copy()
        env["TENETX_CODEX_SKIP_WATCHER"] = "1"
        env["TENETX_CODEX_SKIP_WATCHER_SESSION"] = session_id or ""
        env["TENETX_CODEX_SKIP_WATCHER_STARTED_AT"] = str(time.time() - 5)
        subprocess.Popen(
            [sys.executable, os.path.abspath(script_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
        debug_log("pending_ask_watcher_started session=" + (session_id[:20] if session_id else "none"))
    except Exception as exc:
        debug_log("pending_ask_watcher_start_error=" + type(exc).__name__ + " " + str(exc)[:120])


def _run_skip_feedback_watcher():
    session_id = os.environ.get("TENETX_CODEX_SKIP_WATCHER_SESSION", "")
    started_at_raw = os.environ.get("TENETX_CODEX_SKIP_WATCHER_STARTED_AT", "")
    try:
        started_at = float(started_at_raw) if started_at_raw else None
    except Exception:
        started_at = None
    deadline = time.time() + max(1, SKIP_WATCHER_SECONDS)
    while time.time() < deadline:
        flush_pending_codex_skip_feedback(session_id=session_id)
        flush_native_codex_rejection_feedback(session_id=session_id, since_ts=started_at)
        time.sleep(max(0.2, SKIP_WATCHER_INTERVAL_SECONDS))


def _semantic_tool_input_for_correlation(tool_input):
    """Drop transport metadata so PreToolUse and PermissionRequest hash equal."""
    if not isinstance(tool_input, dict):
        return {}
    ignored = {
        "raw_tool_name",
        "outer_tool_name",
        "carrier_input",
        "connector_server",
        "connector_app",
        "connector_action",
        "connector_tool_name",
        "server_id",
        "mcp_server_id",
        "mcp_tool_name",
    }
    return {
        key: value
        for key, value in tool_input.items()
        if key not in ignored and not str(key).startswith("_tenetx_")
    }


def get_vmcp_correlation_id(hook_input):
    """Extract a stable per-tool-call correlation ID from the hook payload.

    Prefer vendor tool-call ids. Codex event ``id`` / ``request_id`` / ``trace_id``
    are per hook invocation, so PreToolUse and PermissionRequest would otherwise
    audit as two actions. When Codex omits a call id, hash session + tool +
    semantic input so both policy hooks share one identity.
    Session identifiers alone are never used: that collapses many actions.
    """
    for key in (
        "tool_use_id",
        "tool_call_id",
        "tool_callId",
        "toolUseId",
        "call_id",
    ):
        value = hook_input.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    if hook_input.get("hook_event_name") == "PermissionRequest":
        pending_id = _pending_permission_call_id(hook_input)
        if pending_id:
            return pending_id
    session_id = get_session_id(hook_input)
    tool_name = str(hook_input.get("tool_name") or "").strip().lower()
    try:
        payload = json.dumps(
            _semantic_tool_input_for_correlation(hook_input.get("tool_input")),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
    except Exception:
        payload = str(hook_input.get("tool_input") or "")
    material = session_id + "|" + tool_name + "|" + payload
    return "tenetx:call:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _pending_permission_call_id(hook_input):
    """Attach an id-less native approval to its one pending tool attempt.

    Codex can supply a call id in PreToolUse but omit it in PermissionRequest.
    Reuse the existing ASK record only within the same turn and exact operation.
    Ambiguous concurrent attempts remain separate; never guess the approval owner.
    """
    session_id = get_session_id(hook_input)
    turn_id = hook_input.get("turn_id")
    if not session_id or not turn_id:
        return None
    tool_name = normalize_tool_name(hook_input.get("tool_name") or "")
    tool_input = hook_input.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return None
    semantic = _semantic_tool_input_for_correlation(
        normalize_tool_input(tool_name, tool_input, tool_input.get("raw_tool_name"))
    )
    try:
        matches = {
            record["tool_call_id"]
            for record in _iter_pending_asks(session_id)
            if record.get("session_id") == session_id
            and record.get("turn_id") == turn_id
            and record.get("tool_name") == tool_name
            and record.get("decision_id")
            and record.get("tool_call_id")
            and _semantic_tool_input_for_correlation(record.get("tool_input")) == semantic
        }
    except (OSError, ValueError, TypeError) as exc:
        _record_capture_failure("codex", "/approval-correlation", exc, hook_input)
        return None
    if len(matches) == 1:
        return next(iter(matches))
    if len(matches) > 1:
        _record_capture_failure(
            "codex", "/approval-correlation",
            ValueError("ambiguous pending approval identity"), hook_input,
        )
    return None


def get_session_id(hook_input):
    """Extract session ID from Codex hook payload."""
    for key in ("session_id", "sessionId", "conversation_id", "conversationId"):
        value = hook_input.get(key)
        if value is not None:
            text = str(value).strip()
            if text:
                return text
    return ""


def direct_feedback_context(result):
    if not isinstance(result, dict) or not result.get("resolved"):
        return None
    prompt = result.get("direct_feedback_prompt")
    if not isinstance(prompt, dict):
        return None
    message = prompt.get("message")
    return message if isinstance(message, str) and message.strip() else None


def send_decision_feedback(hook_input, tool_name, session_id, vmcp_correlation_id, status="approved", reason=None, tool_input=None):
    payload = {
        "client_surface": CLIENT_SURFACE,
        "tool_name": tool_name,
        "session_id": session_id,
        "tool_call_id": vmcp_correlation_id,
        "tool_use_id": vmcp_correlation_id,
        "request_id": vmcp_correlation_id,
        "id": vmcp_correlation_id,
        "trace_id": vmcp_correlation_id,
        "agent_id": socket.gethostname(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "user_email": os.environ.get("TENETX_USER_EMAIL", ""),
        "status": status,
    }
    if reason:
        payload["reason"] = reason
    if isinstance(tool_input, dict):
        payload["tool_input"] = tool_input
    if reason in (
        "codex_native_permission_rejected",
        "codex_native_permission_skipped",
        "codex_native_permission_denied",
        "codex_native_permission_approved",
        "codex_native_permission_modified",
    ):
        payload["guardrail_origin"] = "agent_native_guardrail"
        payload["native_guardrail_actor"] = "codex"
        if reason.endswith("_approved"):
            payload["native_guardrail_action"] = "ask"
        elif reason.endswith("_modified"):
            payload["native_guardrail_action"] = "modified"
        else:
            payload["native_guardrail_action"] = "deny"
    for key in ("decision_id", "policy_decision_id"):
        value = hook_input.get(key)
        if isinstance(value, str) and value.strip():
            payload["decision_id"] = value.strip()
            break

    url = TENETX_URL + "/api/vmcp/" + TENETX_ORG + "/codex/decision-feedback"
    try:
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if VMCP_TOKEN:
            headers["Authorization"] = "Bearer " + VMCP_TOKEN
        req = urllib.request.Request(
            url,
            data=_json_payload(payload, urlparse(url).path),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT) as response:
            result = json.load(response)
        debug_log("decision_feedback_ok")
        write_posture_marker(POSTURE_HEALTHY_VALUE, "tenetx_api_verified", "/codex/decision-feedback")
        result_body = result if isinstance(result, dict) else {}
        rca_log(
            "decision_feedback_ok",
            tool_call_id=vmcp_correlation_id,
            session_id=session_id,
            decision_id=result_body.get("decision_id") or payload.get("decision_id") or "",
            status=status,
            resolved=result_body.get("resolved"),
            final_outcome=result_body.get("final_outcome"),
        )
        return result
    except Exception as e:
        debug_log("decision_feedback_error=" + type(e).__name__ + " " + str(e)[:160])
        write_posture_marker(POSTURE_UNHEALTHY_VALUE, "tenetx_api_error:" + type(e).__name__, "/codex/decision-feedback")
        rca_log(
            "decision_feedback_error",
            tool_call_id=vmcp_correlation_id,
            session_id=session_id,
            decision_id=payload.get("decision_id") or "",
            status=status,
            error_type=type(e).__name__,
        )
        return None


def resolve_unsupported_ask(
    hook_input,
    result,
    tool_name,
    tool_input,
    session_id,
    vmcp_correlation_id,
    reason,
):
    """Resolve a fail-closed ASK without inventing a timeout or user vote."""
    feedback_input = dict(hook_input or {})
    if isinstance(result, dict):
        decision_id = result.get("decision_id")
        if isinstance(decision_id, str) and decision_id.strip():
            feedback_input["decision_id"] = decision_id.strip()
    return send_decision_feedback(
        feedback_input,
        tool_name,
        session_id,
        vmcp_correlation_id,
        status="unsupported_surface",
        reason=reason,
        tool_input=tool_input,
    )



_AGENT_RAW_DUMP_MAX_BYTES = 50 * 1024 * 1024
_AGENT_RAW_DUMP_TRUTHY = ("1", "true", "yes", "on")
_AGENT_RAW_DUMP_FALSY = ("0", "false", "no", "off")


def _agent_raw_dump_enabled():
    saw_explicit_off = False
    for name in ("TENETX_AGENT_RAW_DUMP", "TENETX_CURSOR_RAW_DUMP"):
        env = str(os.environ.get(name) or "").strip().lower()
        if env in _AGENT_RAW_DUMP_TRUTHY:
            return True
        if env in _AGENT_RAW_DUMP_FALSY:
            saw_explicit_off = True
    if saw_explicit_off:
        return False
    try:
        home = Path.home() / ".tenetx"
        if (home / "agent_raw_dump").is_file():
            return True
        return (home / (str(HOOK_TYPE) + "_raw_dump")).is_file()
    except OSError:
        return False


def _dump_agent_raw(raw_stdin, event=None, stage="stdin"):
    """Persist one verbatim agent hook emission. Never raises."""
    if not _agent_raw_dump_enabled():
        return
    try:
        log_dir = Path.home() / ".tenetx" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(log_dir, 0o700)
        except OSError:
            pass
        path = log_dir / (str(HOOK_TYPE) + "_raw.jsonl")
        if path.is_file() and path.stat().st_size >= _AGENT_RAW_DUMP_MAX_BYTES:
            rotated = log_dir / (str(HOOK_TYPE) + "_raw.jsonl.1")
            try:
                if rotated.exists():
                    rotated.unlink()
                path.replace(rotated)
            except OSError:
                pass
        record = {
            "ts": time.time(),
            "hook_type": HOOK_TYPE,
            "stage": stage,
            "hook_event_name": None,
            "tool_name": None,
            "raw_stdin": raw_stdin,
            "event": event,
        }
        if isinstance(event, dict):
            record["hook_event_name"] = (
                event.get("hook_event_name")
                or event.get("hook_event")
                or event.get("event")
            )
            record["tool_name"] = (
                event.get("tool_name") or event.get("tool") or event.get("name")
            )
        line = json.dumps(record, default=str, ensure_ascii=False)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception as exc:
        recorder = globals().get("_record_capture_failure")
        if callable(recorder):
            try:
                recorder(
                    HOOK_TYPE,
                    "/agent-raw-dump",
                    exc,
                    event if isinstance(event, dict) else None,
                )
            except Exception:
                pass



def main():
    if os.environ.get("TENETX_CODEX_SKIP_WATCHER") == "1":
        _run_skip_feedback_watcher()
        sys.exit(0)

    raw_stdin = sys.stdin.read()
    try:
        hook_input = json.loads(raw_stdin)
    except Exception as e:
        debug_log("hook_input_parse_error: " + str(e))
        _dump_agent_raw(raw_stdin, None, "stdin_json_error")
        sys.exit(0)
    # Verbatim Codex emission, before normalization or /check extract.
    _dump_agent_raw(raw_stdin, hook_input, "stdin")

    hook_event = hook_input.get("hook_event_name", "PreToolUse")
    raw_tool_name = hook_input.get("tool_name", "")
    raw_tool_input = hook_input.get("tool_input", {})
    tool_name = normalize_tool_name(raw_tool_name)
    tool_input = normalize_tool_input(tool_name, raw_tool_input, raw_tool_name)
    session_id = get_session_id(hook_input)
    hook_input = _enrich_codex_runtime_context(hook_input, session_id)

    if not TENETX_URL or not TENETX_ORG:
        sys.exit(0)

    if hook_event == "SessionStart":
        try:
            if _maybe_refresh_codex_browser_bundle():
                debug_log("browser_bundle_reconciled")
        except Exception as browser_bundle_error:
            debug_log(
                "browser_bundle_reconcile_failed="
                + type(browser_bundle_error).__name__
                + " "
                + str(browser_bundle_error)[:160]
            )
            _record_capture_failure(
                "codex",
                "/browser-bundle",
                browser_bundle_error,
                hook_input,
            )

    _maybe_auto_update(hook_event)
    debug_log(
        "hook_event=" + hook_event
        + " tool=" + tool_name
        + " raw_tool=" + str(raw_tool_name)
        + " session=" + (session_id[:20] if session_id else "none")
    )
    if hook_event == "SessionStart":
        _start_skip_feedback_watcher(session_id)
        signin = _signin_remediation(VMCP_TOKEN)
        if signin:
            print(json.dumps({"systemMessage": signin}))
    if hook_event != "PermissionRequest":
        flush_pending_codex_skip_feedback(session_id=session_id)
        flush_native_codex_rejection_feedback(session_id=session_id)

    # Policy-bearing hooks must send/receive their security decision before
    # performing capture I/O. Their authoritative evidence is already written
    # by /check; raw transcript capture happens on non-policy lifecycle/tool
    # completion events and at Stop.
    if hook_event not in ("PreToolUse", "PermissionRequest", "UserPromptSubmit"):
        _capture_event(hook_input, hook_event, session_id)
    if hook_event in ("Stop", "SubagentStop", "SessionEnd"):
        _start_codex_terminal_refresh(hook_input, hook_event, session_id)

    # -- Lifecycle events: fire-and-forget to /lifecycle endpoint --
    if hook_event in ("SessionStart", "Stop", "SessionEnd", "SubagentStart", "SubagentStop", "PreCompact", "PostCompact"):
        _dispatch_lifecycle(hook_input, hook_event, session_id)
        sys.exit(0)

    if hook_event == "PreToolUse":
        handle_pre_tool_use(hook_input, tool_name, tool_input, session_id)
        return

    if hook_event == "PermissionRequest":
        handle_permission_request(hook_input, tool_name, tool_input, session_id)
        return

    if hook_event == "PostToolUse":
        handle_post_tool_use(hook_input, tool_name, tool_input, session_id)
        return

    if hook_event == "UserPromptSubmit":
        handle_prompt_submit(hook_input, session_id)
        return

    sys.exit(0)


def _dispatch_lifecycle(hook_input, event_name, session_id):
    """Send lifecycle event to the /lifecycle endpoint (fire-and-forget)."""
    payload = {
        "client_surface": CLIENT_SURFACE,
        "event": event_name,
        "session_id": session_id,
        "agent_id": socket.gethostname(),
        "user_email": os.environ.get("TENETX_USER_EMAIL", ""),
        "hook_version": os.environ.get("TENETX_GUARD_VERSION", "unknown"),
        "zscaler_posture": posture_evidence(),
    }
    if event_name == "SessionStart":
        payload["model"] = hook_input.get("model", "")
        payload["permission_mode"] = hook_input.get("permission_mode", "")
        payload["cwd"] = hook_input.get("cwd", "")
    elif event_name == "Stop":
        payload["stop_hook_active"] = hook_input.get("stop_hook_active", False)

    _merge_skill_inventory(payload, session_id=session_id)

    url = TENETX_URL + "/api/vmcp/" + TENETX_ORG + "/codex/lifecycle"
    try:
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if VMCP_TOKEN:
            headers["Authorization"] = "Bearer " + VMCP_TOKEN
        req = urllib.request.Request(
            url,
            data=_json_payload(payload, urlparse(url).path),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT) as response:
            response.read()
        debug_log("lifecycle_" + event_name + "_ok")
        write_posture_marker(POSTURE_HEALTHY_VALUE, "tenetx_api_verified", "/codex/lifecycle")
    except Exception as e:
        debug_log("lifecycle_" + event_name + "_error=" + type(e).__name__ + " " + str(e)[:100])
        write_posture_marker(POSTURE_UNHEALTHY_VALUE, "tenetx_api_error:" + type(e).__name__, "/codex/lifecycle")
    # Always succeed -- lifecycle events must never block


# Capture wiring (_capture_event etc.) is injected here from codex_capture.py at render time;
# it runs in this rendered hook's scope and uses its helpers/globals (kept out of the god-file).
_CAPTURE_FAILURES_MAX_LINES = 200
_CAPTURE_RETRY_MAX_ENTRIES = 100
_CAPTURE_RETRYABLE_STATUS = (408, 425, 429, 500, 502, 503, 504)
_CAPTURE_RETRY_DELAYS = (0.2,)
_CAPTURE_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024
_CAPTURE_MAX_MESSAGES_PER_CHUNK = 1900
_CAPTURE_CHUNK_SIZE_MARGIN = 4096


def _capture_payload_chunks(payload):
    """Bound both streams without dropping rows; retain global message offsets.

    Codex usage chunks carry the preceding cumulative counter and model hint.
    Replaying that anchor is idempotent in storage and preserves token deltas.
    Only the first chunk owns the lifecycle delivery.
    """
    if not isinstance(payload, dict):
        return [payload]
    messages = payload.get("transcript_messages") or []
    usage = payload.get("transcript_usage") or []
    if not isinstance(messages, list) or not isinstance(usage, list):
        raise ValueError("capture streams must be lists")
    # Claude blocks repeat per-response usage. Resolve the final snapshot
    # before splitting so storage cannot freeze an earlier block's counters.
    usage_indexes = {}
    compact_usage = []
    for row in usage:
        message = row.get("message") if isinstance(row, dict) else None
        key = message.get("id") if isinstance(message, dict) else None
        if key and isinstance(message.get("usage"), dict):
            if key in usage_indexes:
                compact_usage[usage_indexes[key]] = row
                continue
            usage_indexes[key] = len(compact_usage)
        compact_usage.append(row)
    if len(compact_usage) != len(usage):
        usage = compact_usage
        payload = dict(payload, transcript_usage=usage)
    size = lambda value: len(json.dumps(value, separators=(",", ":")).encode("utf-8"))
    if (len(messages) <= _CAPTURE_MAX_MESSAGES_PER_CHUNK
            and len(usage) <= _CAPTURE_MAX_MESSAGES_PER_CHUNK
            and size(payload) <= _CAPTURE_MAX_PAYLOAD_BYTES):
        return [payload]
    base = {key: value for key, value in payload.items()
            if key not in ("transcript_messages", "transcript_usage", "capture_delivery_id")}
    raw_offset = payload.get("transcript_message_seq_offset", 0)
    offset = raw_offset if isinstance(raw_offset, int) and raw_offset >= 0 else 0
    chunks = []
    anchor = None
    model = None
    for key, rows in (("transcript_usage", usage), ("transcript_messages", messages)):
        current = []
        first_index = 0
        current_size = size(base) + _CAPTURE_CHUNK_SIZE_MARGIN
        for index, row in enumerate(rows):
            row_size = size(row) + 1
            if current and (len(current) >= _CAPTURE_MAX_MESSAGES_PER_CHUNK
                            or current_size + row_size > _CAPTURE_MAX_PAYLOAD_BYTES):
                chunk = dict(base)
                chunk[key] = current
                if key == "transcript_messages":
                    chunk["transcript_message_seq_offset"] = offset + first_index
                chunks.append(chunk)
                current = []
                if key == "transcript_usage":
                    current = [value for value in (
                        model, dict(anchor, _tenetx_usage_anchor=True) if anchor else None
                    ) if value is not None]
                first_index = index
                current_size = size(base) + size(current) + _CAPTURE_CHUNK_SIZE_MARGIN
            if current_size + row_size > _CAPTURE_MAX_PAYLOAD_BYTES:
                raise ValueError("capture row exceeds upload limit")
            current.append(row)
            current_size += row_size
            if key == "transcript_usage" and isinstance(row, dict):
                pl = row.get("payload") if isinstance(row.get("payload"), dict) else row
                if pl.get("type") == "token_count":
                    anchor = row
                if pl.get("model"):
                    model = {"type": "model_hint", "model": pl["model"]}
        if current:
            chunk = dict(base)
            chunk[key] = current
            if key == "transcript_messages":
                chunk["transcript_message_seq_offset"] = offset + first_index
            chunks.append(chunk)
    for index, chunk in enumerate(chunks):
        if index:
            chunk["transcript_only"] = True
        elif payload.get("capture_delivery_id"):
            chunk["capture_delivery_id"] = payload["capture_delivery_id"]
    return chunks or [payload]


def _post_transcript_capture(payload):
    """Used by every shared-hook terminal refresh, including delayed flushes."""
    delivered = True
    try:
        for chunk in _capture_payload_chunks(payload):
            delivered = bool(_http_post(
                f"/api/vmcp/{ORG_SLUG}/{HOOK_TYPE}/capture", chunk, fire_and_forget=True
            )) and delivered
    except Exception as exc:
        _record_capture_failure(HOOK_TYPE, "/transcript-upload", exc, payload)
        return False
    return delivered


def _record_capture_failure(hook, path, exc, payload):
    """Append one bounded JSONL breadcrumb for a failed /capture POST.

    Capture uploads are fire-and-forget, so without a local trace a broken
    capture pipeline is invisible; `tenetx doctor` reads this file. Best-effort:
    never raises, and the file is truncated to its newest 200 entries. `path`
    must be a bare URL path (no query string / token).
    """
    try:
        raw_event = payload.get("raw_event") if isinstance(payload, dict) else None
        session_id = ""
        if isinstance(raw_event, dict):
            session_id = str(raw_event.get("session_id") or raw_event.get("sessionId") or "")
        status = getattr(exc, "code", None)
        line = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hook": hook,
            "path": path,
            "status": status if isinstance(status, int) else "exception",
            "error": (type(exc).__name__ + ": " + str(exc))[:300],
            "session_id": session_id,
        })
        failures_path = Path.home() / ".tenetx" / "capture_failures.jsonl"
        failures_path.parent.mkdir(parents=True, exist_ok=True)
        with failures_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        lines = failures_path.read_text(encoding="utf-8").splitlines(True)
        if len(lines) > _CAPTURE_FAILURES_MAX_LINES:
            with failures_path.open("w", encoding="utf-8") as handle:
                handle.writelines(lines[-_CAPTURE_FAILURES_MAX_LINES:])
    except Exception:
        pass


def _capture_retry_path():
    return Path.home() / ".tenetx" / "capture_retry_queue"


def _enqueue_capture_retry(hook, path, payload):
    """Persist one retryable capture payload without ever blocking the agent."""
    try:
        queue_path = _capture_retry_path()
        queue_path.mkdir(parents=True, exist_ok=True)
        try:
            queue_path.chmod(0o700)
        except OSError:
            pass
        entry = {
            "queued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hook": hook,
            "path": path,
            "payload": payload,
        }
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(queue_path),
            prefix="capture-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(entry, handle, separators=(",", ":"))
            temporary = Path(handle.name)
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        ready = temporary.with_suffix(".json")
        os.replace(temporary, ready)
        entries = sorted(queue_path.glob("capture-*.json"))
        for stale in entries[:-_CAPTURE_RETRY_MAX_ENTRIES]:
            try:
                stale.unlink()
            except OSError as exc:
                _record_capture_failure(hook, path, exc, payload)
                break
    except Exception as exc:
        _record_capture_failure(hook, path, exc, payload)


def _is_retryable_capture_error(exc):
    status = getattr(exc, "code", None)
    if isinstance(status, int):
        return status in _CAPTURE_RETRYABLE_STATUS
    return isinstance(exc, (urllib.error.URLError, TimeoutError, OSError))


def _retry_capture_immediately(exc):
    """Retry fast transient responses, but do not double an elapsed timeout."""
    if isinstance(exc, TimeoutError) or isinstance(
        getattr(exc, "reason", None), TimeoutError
    ):
        return False
    return _is_retryable_capture_error(exc)


def _drain_capture_retry_queue(send_once, *, max_entries=3):
    """Deliver a few older payloads before the current one.

    The queue is bounded so a long outage cannot grow local disk usage without
    limit. A failed oldest entry and all following entries remain queued.
    """
    queue_path = _capture_retry_path()
    try:
        entries = sorted(queue_path.glob("capture-*.json"))
    except FileNotFoundError:
        return
    except OSError as exc:
        _record_capture_failure(
            "unknown", "/capture-retry-queue", exc, {}
        )
        return
    delivered = 0
    for entry_path in entries:
        if delivered >= max_entries:
            break
        try:
            entry = json.loads(entry_path.read_text(encoding="utf-8"))
            if not isinstance(entry, dict):
                raise ValueError("capture retry entry is not an object")
        except Exception as exc:
            _record_capture_failure(
                "unknown", "/capture-retry-queue", exc, {}
            )
            try:
                entry_path.unlink()
            except OSError as unlink_exc:
                _record_capture_failure(
                    "unknown", "/capture-retry-queue", unlink_exc, {}
                )
                break
            continue
        try:
            send_once(str(entry.get("path") or ""), entry.get("payload") or {})
        except Exception as exc:
            if _is_retryable_capture_error(exc):
                break
            _record_capture_failure(
                str(entry.get("hook") or "unknown"),
                str(entry.get("path") or ""),
                exc,
                entry.get("payload") or {},
            )
        try:
            entry_path.unlink()
        except OSError as exc:
            _record_capture_failure(
                str(entry.get("hook") or "unknown"),
                str(entry.get("path") or ""),
                exc,
                entry.get("payload") or {},
            )
            break
        delivered += 1


def _capture_post_with_retry(hook, path, payload, send_once):
    """Drain old work, then make two bounded attempts for the current event."""
    if isinstance(payload, dict):
        payload.setdefault("capture_delivery_id", os.urandom(16).hex())
    _drain_capture_retry_queue(send_once)
    last_exc = None
    for attempt in range(len(_CAPTURE_RETRY_DELAYS) + 1):
        try:
            return send_once(path, payload)
        except Exception as exc:
            last_exc = exc
            if not _is_retryable_capture_error(exc):
                break
            if not _retry_capture_immediately(exc):
                break
            if attempt < len(_CAPTURE_RETRY_DELAYS):
                time.sleep(_CAPTURE_RETRY_DELAYS[attempt])
    _record_capture_failure(hook, path, last_exc, payload)
    if last_exc is not None and _is_retryable_capture_error(last_exc):
        _enqueue_capture_retry(hook, path, payload)
    return False



_TERMINAL_CAPTURE_EVENTS = ("Stop", "SubagentStop", "SessionEnd")
_LAST_CODEX_CAPTURE_SIGNATURE = None
_LAST_CODEX_CAPTURE_TERMINAL = False


def _codex_capture_signature(usage, messages):
    last = messages[-1] if messages else {}
    payload = last.get("payload") if isinstance(last.get("payload"), dict) else last
    return (
        len(usage),
        len(messages),
        str(last.get("timestamp") or payload.get("timestamp") or ""),
        str(payload.get("id") or ""),
    )


def _codex_has_terminal_assistant(messages):
    """Require a displayable assistant response after the latest user/tool row."""
    boundary_index = -1
    assistant_index = -1
    for index, row in enumerate(messages):
        if not isinstance(row, dict):
            continue
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else row
        ptype = payload.get("type")
        role = payload.get("role")
        if (ptype == "message" and role == "user") or ptype in (
            "function_call", "local_shell_call", "custom_tool_call",
            "tool_search_call",
        ):
            boundary_index = index
            continue
        if ptype != "message" or role != "assistant":
            continue
        content = payload.get("content")
        if isinstance(content, str) and content.strip():
            assistant_index = index
        elif isinstance(content, list) and any(
            isinstance(block, dict)
            and isinstance(block.get("text"), str)
            and block.get("text").strip()
            for block in content
        ):
            assistant_index = index
    return assistant_index > boundary_index


def _codex_terminal_refresh_delays():
    """Return bounded post-hook refresh delays for rollout flush races."""
    raw = os.environ.get("TENETX_TRANSCRIPT_REFRESH_DELAYS", "0.75,1.5,3.0")
    delays = []
    for value in raw.split(",")[:4]:
        try:
            delay = float(value.strip())
        except ValueError:
            continue
        if 0.05 <= delay <= 5.0:
            delays.append(delay)
    return tuple(delays) or (0.75, 1.5)


def _codex_capture_cursor_path(session_id):
    digest = hashlib.sha256(str(session_id or "unknown").encode("utf-8")).hexdigest()
    return Path.home() / ".tenetx" / "capture_cursors" / "codex" / (digest + ".json")


def _load_codex_capture_cursor(session_id):
    path = _codex_capture_cursor_path(session_id)
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except Exception as exc:
        _record_capture_failure(
            "codex", "/capture-cursor-read", exc,
            {"raw_event": {"session_id": session_id}},
        )
        return {}


def _save_codex_capture_cursor(session_id, state):
    if not isinstance(state, dict) or not state.get("rollout_path"):
        return
    path = _codex_capture_cursor_path(session_id)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix="cursor-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(state, handle, separators=(",", ":"))
            temporary = Path(handle.name)
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    except Exception as exc:
        _record_capture_failure(
            "codex", "/capture-cursor-write", exc,
            {"raw_event": {"session_id": session_id}},
        )


def _read_codex_rollout_streams(session_id):
    """Read this session's Codex rollout JSONL (bounded) and return
    (usage_lines, message_lines, run_context) as raw dicts. The server parses + redacts the
    bounded usage/message streams; run_context contains identifiers only (model, approval,
    sandbox, collaboration, effort), never prompt/context text. Best-effort; never raises."""

    usage = []
    messages = []
    run_context = {}
    stream_state = {}
    message_seq_offset = 0
    try:
        for path in _codex_session_files(session_id):
            try:
                if os.path.getsize(path) > 64 * 1024 * 1024:
                    raise ValueError("rollout exceeds 64 MiB capture limit")
                cursor = _load_codex_capture_cursor(session_id)
                same_rollout = (
                    cursor.get("capture_revision") == 1
                    and cursor.get("rollout_path") == str(path)
                    and isinstance(cursor.get("byte_offset"), int)
                    and 0 <= cursor["byte_offset"] <= os.path.getsize(path)
                )
                start_offset = cursor["byte_offset"] if same_rollout else 0
                prior_message_seq = (
                    int(cursor.get("message_seq") or 0) if same_rollout else 0
                )
                latest_usage_anchor = (
                    cursor.get("usage_anchor") if same_rollout else None
                )
                latest_model_hint = (
                    cursor.get("model_hint") if same_rollout else None
                )
                new_usage = []
                new_message_count = 0
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    if start_offset:
                        handle.seek(start_offset)
                    while True:
                        line_offset = handle.tell()
                        raw_line = handle.readline()
                        if not raw_line:
                            break
                        complete_line = raw_line.endswith("\n")
                        raw_line = raw_line.strip()
                        if not raw_line:
                            continue
                        if len(raw_line) > 1000000:
                            _record_capture_failure("codex", "/transcript-read", ValueError("rollout row exceeds 1M characters"), {})
                            continue
                        try:
                            obj = json.loads(raw_line)
                        except ValueError:
                            if not complete_line:
                                handle.seek(line_offset)
                                break
                            _record_capture_failure("codex", "/transcript-read", ValueError("invalid JSON rollout row"), {})
                            continue
                        if not isinstance(obj, dict):
                            continue
                        pl = obj.get("payload") if isinstance(obj.get("payload"), dict) else obj
                        # Current Codex announces the run configuration on a top-level
                        # turn_context row whose payload has no `type`. Preserve only the small,
                        # non-content fields needed by Sessions; never forward developer text.
                        if obj.get("type") in ("turn_context", "session_meta") or pl.get("type") in (
                                "turn_context", "session_meta"):
                            model = pl.get("model") or obj.get("model")
                            if isinstance(model, str) and model:
                                run_context["model"] = model
                            approval = pl.get("approval_policy") or obj.get("approval_policy")
                            if isinstance(approval, str) and approval:
                                run_context["approval_policy"] = approval
                            sandbox = pl.get("sandbox_policy") or obj.get("sandbox_policy")
                            if isinstance(sandbox, dict) and isinstance(sandbox.get("type"), str):
                                run_context["sandbox_policy"] = sandbox.get("type")
                            permission = pl.get("permission_mode") or obj.get("permission_mode")
                            if isinstance(permission, str) and permission:
                                run_context["permission_mode"] = permission
                            collaboration = pl.get("collaboration_mode") or obj.get("collaboration_mode")
                            if isinstance(collaboration, dict):
                                collaboration = collaboration.get("mode")
                            if isinstance(collaboration, str) and collaboration:
                                run_context["collaboration_mode"] = collaboration
                            effort = pl.get("effort") or obj.get("effort")
                            if isinstance(effort, str) and effort:
                                run_context["reasoning_effort"] = effort
                        if pl.get("type") == "token_count" or isinstance(pl.get("usage"), dict):
                            new_usage.append(obj)
                            latest_usage_anchor = obj
                        elif isinstance(pl.get("model"), str) and pl.get("model"):
                            # token_count rows carry NO model; the model is announced on the
                            # preceding turn_context / session_meta line. Forward a MINIMAL model
                            # hint (never the whole line — it may hold prompt/context) so the
                            # server can attribute every usage row to a model (cost + the
                            # human-vs-agent discriminator). Ordered before its token_count rows.
                            latest_model_hint = {
                                "type": "model_hint",
                                "model": pl.get("model"),
                                "timestamp": obj.get("timestamp"),
                            }
                            new_usage.append(latest_model_hint)
                        ptype = pl.get("type")
                        role = pl.get("role") or obj.get("type")
                        if role in ("user", "assistant", "system") or ptype in (
                                "message", "function_call", "function_call_output", "reasoning",
                                "local_shell_call", "local_shell_call_output",
                                "custom_tool_call", "custom_tool_call_output",
                                "tool_search_call", "tool_search_output"):
                            messages.append(obj)
                            new_message_count += 1
                    end_offset = handle.tell()
                if new_usage:
                    prior_anchor = (
                        cursor.get("usage_anchor") if same_rollout else None
                    )
                    prior_model = (
                        cursor.get("model_hint") if same_rollout else None
                    )
                    if isinstance(prior_model, dict):
                        usage.append(prior_model)
                    if isinstance(prior_anchor, dict):
                        usage.append(prior_anchor)
                    usage.extend(new_usage)
                message_seq_offset = (
                    prior_message_seq + new_message_count - len(messages)
                )
                stream_state = {
                    "capture_revision": 1,
                    "rollout_path": str(path),
                    "byte_offset": end_offset,
                    "message_seq": prior_message_seq + new_message_count,
                    "usage_anchor": latest_usage_anchor,
                    "model_hint": latest_model_hint,
                    "terminal": bool(cursor.get("terminal")) if same_rollout else False,
                }
            except Exception as exc:
                _record_capture_failure("codex", "/transcript-read", exc, {})
                continue
            if stream_state:
                break  # first matching rollout file wins, even with no new lines
    except Exception as exc:
        _record_capture_failure("codex", "/transcript-read", exc, {})
    return (
        list(usage),
        list(messages),
        run_context,
        stream_state,
        message_seq_offset,
    )


def _capture_event(hook_input, hook_event, session_id):
    """Best-effort RAW capture of the lifecycle event into agent_events, decoupled from /check.
    On a terminal event it ALSO forwards the rollout transcript's usage + message streams (the
    token-cost + human/agent-origin ground truth); the server parses + redacts. OPT-IN: gated by
    the per-org render-time default below + the TENETX_AGENT_CAPTURE env override. Fire-and-forget
    on the (non-latency-critical) lifecycle path: it never blocks tool calls and never raises."""
    if os.environ.get("TENETX_AGENT_CAPTURE", "1") != "1":
        return
    global _LAST_CODEX_CAPTURE_SIGNATURE, _LAST_CODEX_CAPTURE_TERMINAL
    try:
        raw_event = dict(hook_input) if isinstance(hook_input, dict) else {}
        # The Codex capture adapter reads session_id straight off the raw event, but Codex may key
        # it as sessionId/conversation_id; pin the resolved id so captured rows join the session.
        if session_id:
            raw_event["session_id"] = session_id
        raw_event.setdefault("hook_event_name", hook_event)
        payload = {"raw_event": raw_event}
        if hook_event in _TERMINAL_CAPTURE_EVENTS:
            (
                usage,
                messages,
                run_context,
                stream_state,
                message_seq_offset,
            ) = _read_codex_rollout_streams(session_id)
            if run_context:
                if not raw_event.get("model"):
                    raw_event["model"] = run_context.get("model")
                if not raw_event.get("permission_mode"):
                    raw_event["permission_mode"] = (
                        run_context.get("permission_mode") or run_context.get("sandbox_policy")
                        or run_context.get("approval_policy")
                    )
                if not raw_event.get("model_params"):
                    raw_event["model_params"] = run_context
            if usage:
                payload["transcript_usage"] = usage
            if messages:
                payload["transcript_messages"] = messages
                payload["transcript_message_seq_offset"] = message_seq_offset
            _LAST_CODEX_CAPTURE_SIGNATURE = _codex_capture_signature(
                usage, messages
            )
            _LAST_CODEX_CAPTURE_TERMINAL = (
                _codex_has_terminal_assistant(messages)
                if messages
                else bool(stream_state.get("terminal"))
            )
            stream_state["terminal"] = _LAST_CODEX_CAPTURE_TERMINAL
        if _post_codex_capture(payload):
            if hook_event in _TERMINAL_CAPTURE_EVENTS:
                _save_codex_capture_cursor(session_id, stream_state)
            debug_log("codex_capture_ok event=" + str(hook_event))
        else:
            debug_log("codex_capture_queued event=" + str(hook_event))
    except Exception as exc:
        _record_capture_failure("codex", "/capture-event", exc, {"raw_event": hook_input})
        debug_log("codex_capture_error=" + type(exc).__name__)


def _post_codex_capture(payload):
    delivered = True
    for capture_payload in _capture_payload_chunks(payload):
        delivered = bool(_capture_post_with_retry(
            "codex", "/api/vmcp/" + TENETX_ORG + "/codex/capture", capture_payload,
            _post_codex_capture_once,
        )) and delivered
    return delivered


def _post_codex_capture_once(url_path, payload):
    headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
    if VMCP_TOKEN:
        headers["Authorization"] = "Bearer " + VMCP_TOKEN
    req = urllib.request.Request(
        TENETX_URL + url_path, data=_json_payload(payload), headers=headers, method="POST"
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT) as response:
        response.read()
    return True


def _refresh_codex_terminal_capture(hook_input, session_id):
    """Reread the rollout after Stop so a just-flushed final response is captured."""
    if os.environ.get("TENETX_AGENT_CAPTURE", "1") != "1":
        return
    global _LAST_CODEX_CAPTURE_SIGNATURE, _LAST_CODEX_CAPTURE_TERMINAL
    previous_signature = _LAST_CODEX_CAPTURE_SIGNATURE
    for delay in _codex_terminal_refresh_delays():
        time.sleep(delay)
        (
            usage,
            messages,
            run_context,
            stream_state,
            message_seq_offset,
        ) = _read_codex_rollout_streams(session_id)
        signature = _codex_capture_signature(usage, messages)
        if signature == previous_signature:
            continue
        previous_signature = signature
        _LAST_CODEX_CAPTURE_SIGNATURE = signature
        _LAST_CODEX_CAPTURE_TERMINAL = (
            _codex_has_terminal_assistant(messages)
            if messages
            else bool(stream_state.get("terminal"))
        )
        stream_state["terminal"] = _LAST_CODEX_CAPTURE_TERMINAL
        raw_event = dict(hook_input) if isinstance(hook_input, dict) else {}
        if session_id:
            raw_event["session_id"] = session_id
        raw_event.setdefault("hook_event_name", "Stop")
        if run_context:
            raw_event.setdefault("model", run_context.get("model"))
            raw_event.setdefault(
                "permission_mode",
                run_context.get("permission_mode") or run_context.get("sandbox_policy")
                or run_context.get("approval_policy"),
            )
            raw_event.setdefault("model_params", run_context)
        payload = {"raw_event": raw_event, "transcript_only": True}
        if usage:
            payload["transcript_usage"] = usage
        if messages:
            payload["transcript_messages"] = messages
            payload["transcript_message_seq_offset"] = message_seq_offset
        if usage or messages:
            try:
                if _post_codex_capture(payload):
                    _save_codex_capture_cursor(session_id, stream_state)
                    debug_log("codex_capture_refresh_ok")
                else:
                    debug_log("codex_capture_refresh_queued")
            except Exception as exc:
                _record_capture_failure("codex", "/terminal-transcript-refresh", exc, payload)
                debug_log("codex_capture_refresh_error=" + type(exc).__name__)
        if _LAST_CODEX_CAPTURE_TERMINAL:
            return


def _start_codex_terminal_refresh(hook_input, hook_event, session_id):
    """Run bounded refreshes inline; Codex may reap detached hook descendants."""
    if hook_event in _TERMINAL_CAPTURE_EVENTS and not _LAST_CODEX_CAPTURE_TERMINAL:
        _refresh_codex_terminal_capture(hook_input, session_id)



_SKILL_SCAN_CACHE = {
    "session_id": "",
    "inventory": None,
    "asset_inventory": None,
    "asset_inventories": None,
}
_SKILL_SCAN_ERRORS = []
_SKILL_SCAN_ERROR_COUNT = 0

# Bounded walk: a skills tree lives on a developer laptop and may sit on a
# slow/network mount, so the scan is capped in every dimension.
_SKILL_SCAN_MAX_FILES = 200
_SKILL_SCAN_MAX_BYTES = 262144
_SKILL_SCAN_MAX_DEPTH = 6
_ASSET_SCAN_MAX_FILES = 200
_ASSET_SCAN_MAX_DEPTH = 6
# Cross-process inventory cache. Every hook invocation is a fresh subprocess,
# so the in-memory cache above never survives; this file is what actually
# keeps the scan off the per-tool-call path.
_SKILL_SCAN_CACHE_TTL_SECONDS = 900
# v2 stores MCP/plugin/rule inventory alongside skills. v3 stores the
# WHOLE-DEVICE inventory (every installed agent, not just the running one), so
# an older cache is a miss: reusing it would keep serving a single-agent
# snapshot and the other agents' rows would stay at whatever they last were.
# v4 also stores the agents that scanned EMPTY. A v3 snapshot omitted those, so
# reusing one would keep those agents rowless -- and the page renders a missing
# row as "--", claiming we never looked at an agent we had just read.
_SKILL_SCAN_CACHE_VERSION = 5


def _skill_scan_roots_for_hook(hook_type):
    home = Path.home()
    cwd = Path.cwd()
    relative_roots = {
        "cursor": (".cursor/skills", ".agents/skills"),
        "claude-code": (".claude/skills", ".claude/plugins", ".agents/skills"),
        "codex": (".codex/skills", ".agents/skills"),
        "copilot": (".copilot/skills", ".github/skills", ".agents/skills"),
        "github-copilot": (".copilot/skills", ".github/skills", ".agents/skills"),
        "windsurf": (".codeium/windsurf/skills", ".windsurf/skills", ".agents/skills"),
        "antigravity": (".gemini/antigravity/skills", ".antigravity/skills", ".agents/skills"),
        "qwen-code": (".qwen/skills", ".agents/skills"),
        "hermes": (".hermes/skills", ".agents/skills"),
        "openclaw": (".agents/skills", ".openclaw/skills"),

        "cline": (".cline/skills", ".agents/skills"),
        "augment-code": (
            ".augment/skills",
            ".augment/commands",
            ".claude/skills",
            ".claude/commands",
            ".agents/skills",
        ),
        "kiro": (".kiro/skills", ".agents/skills"),
        "vibe-code": (
            ".vibe/skills",
            ".vibe/prompts",
            ".agents/skills",
        ),
    }.get(str(hook_type or HOOK_TYPE).strip().lower(), (".agents/skills",))
    roots = []
    seen = set()
    for relative in relative_roots:
        for base in (home, cwd):
            candidate = base / relative
            key = str(candidate)
            if key in seen:
                continue
            seen.add(key)
            if candidate.is_dir():
                roots.append(candidate)
    return roots


def _skill_scan_note_error(stage, path, exc):
    """Record a scan failure so it can be breadcrumbed by the caller."""
    global _SKILL_SCAN_ERROR_COUNT
    _SKILL_SCAN_ERROR_COUNT += 1
    if len(_SKILL_SCAN_ERRORS) < 20:
        _SKILL_SCAN_ERRORS.append(
            {"stage": str(stage), "path": str(path), "error": repr(exc)[:200]}
        )


def _skill_scan_read_text(path):
    try:
        if path.stat().st_size > _SKILL_SCAN_MAX_BYTES:
            _skill_scan_note_error("read_text", path, "skill file over size cap")
            return ""
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        _skill_scan_note_error("read_text", path, exc)
        return ""


def _skill_scan_real_root(root):
    """Resolved scan root, for containment checks.

    Resolved ONCE up front so a root that is ITSELF a symlink still scans:
    dotfile managers routinely make ~/.claude a link into a dotfiles repo, and
    comparing against the unresolved path would report nothing for those users.
    Returns "" when the root cannot be resolved, which the caller treats as
    "scan nothing" rather than "allow everything".
    """
    try:
        return str(root.resolve())
    except Exception as exc:
        _skill_scan_note_error("resolve_root", root, exc)
        return ""


def _skill_scan_within(real, real_root):
    """True when a resolved path is the scan root or lies inside it.

    Cycle detection (the ``visited`` set below) is NOT containment. These
    walkers descend from Path.cwd() as well as $HOME, so a symlink committed
    into a repository the developer has just cloned can point anywhere on the
    machine, and the walk would then upload the names and paths it found there.
    relative_to() is used rather than a string prefix so that a sibling
    directory whose name merely starts with the root's -- "/a/rules-old"
    against "/a/rules" -- is not treated as inside it.
    """
    if not real_root:
        return False
    try:
        Path(real).relative_to(Path(real_root))
    except ValueError:
        return False
    return True


def _skill_scan_iter_skill_files(root):
    """Depth-capped, symlink-safe walk yielding SKILL.md files under root."""
    found = []
    stack = [(root, 0)]
    visited = set()
    real_root = _skill_scan_real_root(root)
    while stack:
        if len(found) >= _SKILL_SCAN_MAX_FILES:
            break
        current, depth = stack.pop()
        if depth > _SKILL_SCAN_MAX_DEPTH:
            continue
        try:
            real = str(current.resolve())
        except Exception as exc:
            _skill_scan_note_error("resolve", current, exc)
            continue
        # Guard against symlink cycles, which would otherwise spin forever.
        if not _skill_scan_within(real, real_root):
            _skill_scan_note_error("outside_root", current, "symlink leaves the scan root")
            continue
        if real in visited:
            continue
        visited.add(real)
        try:
            entries = list(current.iterdir())
        except Exception as exc:
            _skill_scan_note_error("iterdir", current, exc)
            continue
        for entry in entries:
            if len(found) >= _SKILL_SCAN_MAX_FILES:
                break
            try:
                if entry.is_dir():
                    stack.append((entry, depth + 1))
                elif entry.name.lower() == "skill.md":
                    found.append(entry)
            except Exception as exc:
                _skill_scan_note_error("stat", entry, exc)
    return found


def _skill_scan_frontmatter_name(text):
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---\n", 4)
    if end == -1:
        return None
    for line in text[4:end].splitlines():
        if line.startswith("name:"):
            return line.split(":", 1)[1].strip().strip("'\"") or None
    return None


def _skill_scan_normalize(text):
    """Collapse whitespace runs so rules survive line wrapping.

    Returns the normalized text plus a map from normalized offset back to the
    original offset, so findings still report real SKILL.md line numbers.
    """
    chars = []
    offsets = []
    prev_space = False
    for idx, ch in enumerate(text):
        if ch.isspace():
            if prev_space:
                continue
            chars.append(" ")
            offsets.append(idx)
            prev_space = True
        else:
            chars.append(ch)
            offsets.append(idx)
            prev_space = False
    return "".join(chars), offsets


def _skill_scan_zero_width_suspicious(text, index):
    before = text[index - 1] if index > 0 else ""
    after = text[index + 1] if index + 1 < len(text) else ""
    neighbours = before + after
    if not neighbours:
        return True
    return all(ord(ch) < 128 for ch in neighbours)


def _skill_scan_hidden_unicode(text, file_name="SKILL.md"):
    """Invisible characters hide instructions from the human review that is
    otherwise the main compensating control, so they are their own finding."""
    bidi = set("‪‫‬‭‮⁦⁧⁨⁩")
    zero_width = set("​‌‍⁠﻿")
    tags, bidis, zeros = [], [], []
    for index, ch in enumerate(text):
        point = ord(ch)
        if 0xE0000 <= point <= 0xE007F:
            tags.append(index)
        elif ch in bidi:
            bidis.append(index)
        elif ch in zero_width and _skill_scan_zero_width_suspicious(text, index):
            zeros.append(index)

    findings = []
    if tags:
        decoded = "".join(
            chr(ord(ch) - 0xE0000) for ch in text if 0xE0020 <= ord(ch) <= 0xE007E
        ).strip()
        findings.append({
            "rule_id": "SKILL_SCAN:HIDDEN_UNICODE",
            "severity": "critical",
            "message": "Skill contains invisible Unicode Tag characters. Decoded: " + decoded[:180],
            "file": file_name,
            "start_line": text.count("\n", 0, tags[0]) + 1,
            "end_line": text.count("\n", 0, tags[-1]) + 1,
            "snippet": (decoded[:240] or "<invisible Unicode Tag characters>"),
        })
    if bidis:
        findings.append({
            "rule_id": "SKILL_SCAN:BIDI_OVERRIDE",
            "severity": "critical",
            "message": "Skill contains bidirectional override characters.",
            "file": file_name,
            "start_line": text.count("\n", 0, bidis[0]) + 1,
            "end_line": text.count("\n", 0, bidis[-1]) + 1,
            "snippet": "<bidirectional override characters>",
        })
    if zeros:
        findings.append({
            "rule_id": "SKILL_SCAN:ZERO_WIDTH_TEXT",
            "severity": "high",
            "message": "Skill contains zero-width characters between ASCII text.",
            "file": file_name,
            "start_line": text.count("\n", 0, zeros[0]) + 1,
            "end_line": text.count("\n", 0, zeros[-1]) + 1,
            "snippet": "<zero-width characters>",
        })
    return findings


def _skill_scan_findings(text, file_name="SKILL.md"):
    import hashlib
    import re

    findings = []
    lines = text.splitlines()
    # Rules run against whitespace-normalized text: a newline between "ignore
    # all previous" and "instructions" must not defeat the rule.
    normalized, offsets = _skill_scan_normalize(text)
    patterns = (
        ("SKILL_SCAN:INSTRUCTION_OVERRIDE", "critical", r"(?i)\b(ignore (?:all )?(?:previous|prior|above)(?: \w+){0,3} instructions|disregard (?:all )?(?:previous|prior|above)(?: \w+){0,3} instructions|do not (?:tell|inform|notify) (?:the )?user|bypass (?:all )?(?:safety|security|guardrails?))\b"),
        ("SKILL_SCAN:EXTERNAL_INSTRUCTION_REF", "critical", r"(?i)\b(follow (?:the )?instructions (?:at|from|in)\s+(?:https?://|references/)|read (?:the )?(?:instructions|prompt|payload) (?:at|from)\s+(?:https?://|references/))\b"),
        ("SKILL_SCAN:REMOTE_FETCH", "critical", r"(?i)(curl\s+[^|;&]*\|\s*(?:ba)?sh\b|wget\s+[^|;&]*\|\s*(?:ba)?sh\b|(?:curl|wget)\s+[^|;&]*\s+-o\s*[^\s]*\s*&&\s*(?:ba)?sh\b)"),
        ("SKILL_SCAN:CONFIG_POISON", "high", r"(?i)\b(modify\s+(?:the\s+)?(?:claude\.md|\.cursor/rules|memory\.md|hooks\.json|settings\.json)|append (?:to )?(?:claude\.md|memory\.md|\.cursor/rules))\b"),
        ("SKILL_SCAN:CREDENTIAL_EXFIL", "high", r"(?i)((?:append|include|add|attach|send|forward|pass)\b[^.\n]{0,80}?(?:environment variable|env var|\$[A-Z][A-Z0-9_]{3,}|api[_ -]?key|access[_ -]?token|secret|credential|password|bearer token)[^.\n]{0,80}?(?:query parameter|query string|header|request|url|endpoint|payload|body)|(?:read|load|cat|open)\b[^.\n]{0,40}?(?:\.env\b|credentials file|\.aws/credentials|\.ssh/id_)[^.\n]{0,60}?(?:send|post|upload|include|forward|transmit))"),
        ("SKILL_SCAN:DATA_ROUTING", "high", r"(?i)((?:forward|send|post|upload|transmit|copy|mirror|report|exfiltrate)\b[^.\n]{0,100}?\b(?:to|at)\s+https?://|before (?:displaying|showing|returning)\b[^.\n]{0,60}?(?:response|output|result))"),
    )
    seen = set()
    for rule_id, severity, pattern in patterns:
        for match in re.finditer(pattern, normalized):
            start_idx = offsets[match.start()] if match.start() < len(offsets) else 0
            end_pos = max(match.start(), match.end() - 1)
            end_idx = offsets[end_pos] if end_pos < len(offsets) else start_idx
            start_line = text.count("\n", 0, start_idx) + 1
            end_line = text.count("\n", 0, end_idx) + 1
            key = (rule_id, start_line, end_line)
            if key in seen:
                continue
            seen.add(key)
            snippet = "\n".join(lines[max(0, start_line - 1):end_line]).strip()
            findings.append({
                "rule_id": rule_id,
                "severity": severity,
                "message": "Skill scanner detected a risky instruction pattern.",
                "file": file_name,
                "start_line": start_line,
                "end_line": end_line,
                "snippet": snippet[:240],
            })
    # allowed-tools: * — accept bare, single- and double-quoted forms.
    wildcard = re.search(
        r"(?im)^allowed-tools:\s*[\'\"]?\*[\'\"]?\s*$",
        text,
    )
    if wildcard:
        wildcard_line = text.count("\n", 0, wildcard.start()) + 1
        findings.append({
            "rule_id": "SKILL_SCAN:WILDCARD_TOOLS",
            "severity": "critical",
            "message": "Skill grants unrestricted tool access via allowed-tools: *.",
            "file": file_name,
            "start_line": wildcard_line,
            "end_line": wildcard_line,
            "snippet": wildcard.group(0).strip()[:240],
        })
    findings.extend(_skill_scan_hidden_unicode(text, file_name=file_name))
    findings.sort(key=lambda item: (item["start_line"], item["rule_id"]))
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    trust_status = "unverified"
    risk_score = 0.0
    if any(item.get("severity") == "critical" for item in findings):
        trust_status = "blocked"
        risk_score = 8.0
    elif findings:
        # Matches the server scanner: findings short of the block threshold mean
        # "needs review", which is not the same as an unscanned skill.
        trust_status = "pending"
        risk_score = 4.0
    return findings, sha, trust_status, risk_score


def _skill_scan_context():
    import hashlib
    return hashlib.sha256((str(Path.home()) + "\n" + str(Path.cwd()) + "\n" + str(HOOK_TYPE)).encode()).hexdigest()


def _skill_scan_prepare_context():
    context = _skill_scan_context()
    if _SKILL_SCAN_CACHE.get("context") != context:
        _SKILL_SCAN_CACHE.clear()
        _SKILL_SCAN_CACHE["context"] = context


def _skill_scan_cache_path():
    return Path.home() / ".tenetx" / "skill_scan_cache.json"


def _skill_scan_cache_load(session_id):
    import time

    if not session_id:
        return None
    try:
        path = _skill_scan_cache_path()
        if not path.is_file():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        _skill_scan_note_error("cache_load", "skill_scan_cache.json", exc)
        return None
    if not isinstance(raw, dict) or raw.get("session_id") != session_id or raw.get("context") != _skill_scan_context():
        return None
    try:
        if int(raw.get("v") or 1) < _SKILL_SCAN_CACHE_VERSION:
            return None
        age = time.time() - float(raw.get("cached_at") or 0)
    except Exception:
        return None
    if age < 0 or age > _SKILL_SCAN_CACHE_TTL_SECONDS:
        return None
    return raw


def _skill_scan_cache_hydrate(session_id, raw):
    if not isinstance(raw, dict):
        return
    _SKILL_SCAN_CACHE["session_id"] = session_id
    inventory = raw.get("inventory")
    if isinstance(inventory, dict):
        _SKILL_SCAN_CACHE["inventory"] = dict(inventory)
    assets = raw.get("asset_inventory")
    if isinstance(assets, dict):
        _SKILL_SCAN_CACHE["asset_inventory"] = dict(assets)
    device_assets = raw.get("asset_inventories")
    if isinstance(device_assets, list):
        _SKILL_SCAN_CACHE["asset_inventories"] = [
            dict(item) for item in device_assets if isinstance(item, dict)
        ]


def _skill_scan_cache_store(
    session_id, inventory, asset_inventory=None, asset_inventories=None
):
    import time

    if not session_id:
        return
    try:
        path = _skill_scan_cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "session_id": session_id,
                    "cached_at": time.time(),
                    "v": _SKILL_SCAN_CACHE_VERSION,
                    "context": _skill_scan_context(),
                    "inventory": inventory,
                    "asset_inventory": asset_inventory,
                    "asset_inventories": asset_inventories,
                }
            ),
            encoding="utf-8",
        )
    except Exception as exc:
        _skill_scan_note_error("cache_store", "skill_scan_cache.json", exc)


def _asset_scan_hook_key(hook_type):
    return str(hook_type or HOOK_TYPE).strip().lower()


def _asset_scan_json_object(path):
    text = _skill_scan_read_text(path)
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except Exception as exc:
        _skill_scan_note_error("asset_json", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _asset_nested_get(data, dotted):
    current = data
    for part in str(dotted or "").split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


# Container key(s) holding a server map in a JSON MCP config. Both spellings
# are live and they are NOT interchangeable per vendor: Cursor / Claude /
# Windsurf / Qwen write `mcpServers`, while VS Code's own `mcp.json` (the file
# GitHub Copilot and every VS Code MCP extension write) uses `servers`. Reading
# only `mcpServers` from a VS Code file finds nothing at all -- which is why a
# machine with a working Copilot MCP server still reported 0.
_ASSET_MCP_JSON_CONTAINERS = ("mcpServers", "servers")


def _asset_editor_user_dirs(app_names):
    """Per-platform `<editor>/User` config dirs for VS Code-family editors.

    VS Code and its forks (Cursor, Windsurf) keep user-level MCP servers in the
    editor's own profile directory, NOT in the agent's dotfile tree. An MCP
    server installed from the editor's UI or by an extension lands here and
    nowhere else, so a scan that reads only ~/.cursor/mcp.json undercounts
    every server the developer added through the editor.
    """
    import os
    import sys

    home = Path.home()
    dirs = []
    for app in app_names:
        if sys.platform == "darwin":
            dirs.append(home / "Library" / "Application Support" / app / "User")
        elif os.name == "nt":
            appdata = os.environ.get("APPDATA") or ""
            if appdata:
                dirs.append(Path(appdata) / app / "User")
        else:
            xdg = os.environ.get("XDG_CONFIG_HOME") or ""
            base = Path(xdg) if xdg else home / ".config"
            dirs.append(base / app / "User")
    return dirs


def _asset_scan_mcp_specs(hook_type):
    """Home/cwd-relative MCP config files for one agent, as (path, key, kind)."""
    key = _asset_scan_hook_key(hook_type)
    json_keys = _ASSET_MCP_JSON_CONTAINERS
    specs = {
        # Deliberately NOT .vscode/mcp.json. Cursor is a VS Code fork and does
        # read it, but that file is Copilot's canonical location, and the
        # cross-hook attribution in _asset_claim_unseen charges each file to the
        # first agent that reports it -- Cursor sorts first, so listing it here
        # took the workspace server away from Copilot and dropped Copilot off
        # the device entirely. Cursor's own locations are ~/.cursor/mcp.json,
        # the project .cursor/mcp.json, and its editor profile below.
        "cursor": ((".cursor/mcp.json", json_keys, "json"),),
        "claude-code": (
            # "claude-json" additionally reads projects.<path>.mcpServers, which
            # is where `claude mcp add` puts a project-scoped server.
            (".claude.json", json_keys, "claude-json"),
            (".mcp.json", json_keys, "json"),
            (".claude/mcp.json", json_keys, "json"),
        ),
        "windsurf": (
            (".windsurf/mcp.json", json_keys, "json"),
            # The path Windsurf itself writes; ~/.codeium/windsurf is already
            # this agent's skills root, so the tree is the right one.
            (".codeium/windsurf/mcp_config.json", json_keys, "json"),
        ),
        "openclaw": ((".openclaw/openclaw.json", "mcp.servers", "json"),),
        "copilot": ((".vscode/mcp.json", json_keys, "json"),),
        "github-copilot": ((".vscode/mcp.json", json_keys, "json"),),
        "codex": ((".codex/config.toml", "mcp_servers", "toml"),),
        "antigravity": (
            (".gemini/antigravity/mcp.json", json_keys, "json"),
            (".antigravity/mcp_config.json", json_keys, "json"),
        ),
        "qwen-code": (
            (".qwen/settings.json", json_keys, "json"),
            (".qwen/mcp.json", json_keys, "json"),
        ),
        # Hermes declares MCP servers under `mcp_servers` (snake_case) inside
        # the same config.yaml that holds its hook wiring -- read by the
        # minimal YAML scanner below, since the guard is stdlib-only.
        "hermes": ((".hermes/config.yaml", "mcp_servers", "yaml"),),

        "augment-code": (
            (".augment/settings.json", "mcpServers", "json"),
            (".augment/mcp.json", "mcpServers", "json"),
        ),
        "cline": (
            (".cline/data/settings/cline_mcp_settings.json", "mcpServers", "json"),
        ),
        "kiro": ((".kiro/settings/mcp.json", "mcpServers", "json"),),
        "vibe-code": ((".vibe/config.toml", "mcp_servers", "toml"),),
    }.get(key, ())
    return specs


def _asset_scan_mcp_editor_specs(hook_type):
    """Absolute editor-profile MCP configs, as (path, key, kind).

    Separate from the relative specs because these paths are absolute and
    platform-dependent rather than $HOME/$CWD-relative.
    """
    key = _asset_scan_hook_key(hook_type)
    apps = {
        "copilot": ("Code", "Code - Insiders", "VSCodium"),
        "github-copilot": ("Code", "Code - Insiders", "VSCodium"),
        "cursor": ("Cursor",),
        "windsurf": ("Windsurf",),
    }.get(key, ())
    specs = []
    for directory in _asset_editor_user_dirs(apps):
        specs.append((directory / "mcp.json", _ASSET_MCP_JSON_CONTAINERS, "json"))
    return tuple(specs)


def _asset_mcp_names_from_map(servers, path):
    if not isinstance(servers, dict):
        return []
    items = []
    for name, spec in servers.items():
        name_text = str(name).strip()
        if not name_text:
            continue
        # An explicitly disabled server is configured but not running, and
        # counting it overstates the device's live MCP surface.
        if isinstance(spec, dict) and spec.get("enabled") is False:
            continue
        items.append({"name": name_text, "path": str(path)})
    return items


def _asset_scan_mcp_from_json(path, container):
    """Servers under any of `container` (a key, or a tuple of candidate keys)."""
    data = _asset_scan_json_object(path)
    containers = (container,) if isinstance(container, str) else tuple(container or ())
    items = []
    for candidate in containers:
        items.extend(
            _asset_mcp_names_from_map(_asset_nested_get(data, candidate), path)
        )
    return items


def _asset_scan_mcp_from_claude_json(path, container):
    """Top-level AND project-scoped servers in ~/.claude.json.

    `claude mcp add` without --scope user writes the server under
    projects.<abs path>.mcpServers, so a developer who added their servers per
    repo -- the default -- had every one of them invisible to a scan that read
    only the top-level map.
    """
    data = _asset_scan_json_object(path)
    items = _asset_scan_mcp_from_json(path, container)
    projects = data.get("projects")
    if isinstance(projects, dict):
        for entry in projects.values():
            if not isinstance(entry, dict):
                continue
            items.extend(_asset_mcp_names_from_map(entry.get("mcpServers"), path))
    return items


def _asset_scan_mcp_from_yaml(path, container):
    """Server names under a top-level YAML mapping key, without a YAML parser.

    Hermes is the only agent that declares MCP servers in YAML, and the guard
    is stdlib-only (no pyyaml on a developer laptop), so this reads exactly
    what the inventory needs -- the child keys one level under
    ``mcp_servers:`` -- and nothing else.

    Deliberately narrow. Values, anchors and flow-style mappings are out of
    scope: a wrong VALUE would be a silent inventory lie, whereas a missed
    NAME shows up as a lower count that a human can notice. Comments and
    blank lines are skipped; a column-0 line ends the block.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        _skill_scan_note_error("asset_yaml", path, exc)
        return []
    lines = text.splitlines()
    start = -1
    for index, line in enumerate(lines):
        if line.startswith(container) and line[len(container):].lstrip().startswith(":"):
            start = index
            break
    if start < 0:
        return []
    items = []
    child_indent = None
    for line in lines[start + 1:]:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            break
        if child_indent is None:
            child_indent = indent
        if indent != child_indent or ":" not in stripped:
            continue
        name = stripped.split(":", 1)[0].strip().strip('"').strip("'")
        if name and not name.startswith("-"):
            items.append({"name": name, "path": str(path)})
    return items


def _asset_toml_table_server(key_path):
    """First key segment of a TOML table path, honouring quoted keys.

    ``[mcp_servers.github.env]`` is a SUB-TABLE of the ``github`` server (the
    standard way Codex configures a server's environment), not a second
    server — counting it as one inflates mcp_count and uploads a phantom
    "github.env" server into the device inventory. And
    ``[mcp_servers."my.server"]`` is a single server whose name contains a
    dot, so splitting naively on "." would mangle it.
    """
    text = key_path.strip()
    if not text:
        return ""
    if text[:1] in ('"', "'"):
        quote = text[0]
        end = text.find(quote, 1)
        if end == -1:
            return text[1:].strip()
        return text[1:end]
    return text.split(".", 1)[0].strip()


def _asset_toml_tables(text):
    """(header, body) for every `[table]` in a TOML document, in order.

    Enough TOML to read a header and the scalar keys directly beneath it, which
    is all the inventory needs. A real parser is not available: the guard is
    stdlib-only and must run on a laptop Python with no third-party packages,
    and 3.10 has no tomllib.
    """
    import re

    tables = []
    matches = list(re.finditer(r"(?m)^\[([^\]]+)\]\s*$", text))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        tables.append((match.group(1), text[match.end():end]))
    return tables


def _asset_toml_bool(body, key):
    """True/False for `key = true|false` in a table body, else None (unset)."""
    import re

    match = re.search(
        r"(?m)^\s*" + re.escape(key) + r"\s*=\s*(true|false)\s*(?:#.*)?$", body
    )
    if match is None:
        return None
    return match.group(1) == "true"


def _asset_toml_child_key(header, prefix):
    """Server/plugin name in `[<prefix>.<name>]`, plus whether it is the OWN
    table rather than a sub-table such as `[mcp_servers.github.env]`."""
    if not header.startswith(prefix):
        return "", False
    remainder = header[len(prefix):]
    name = _asset_toml_table_server(remainder)
    if not name:
        return "", False
    # Re-derive what the name consumed so a quoted key containing dots
    # ("my.server") is not mistaken for a sub-table path.
    stripped = remainder.strip()
    if stripped[:1] in ('"', "'"):
        consumed = len(name) + 2
    else:
        consumed = len(name)
    is_own_table = stripped[consumed:].strip() == ""
    return name, is_own_table


def _asset_scan_mcp_array_from_toml(path):
    import re

    text = _skill_scan_read_text(path)
    if not text:
        return []
    items = []
    seen = set()
    # Codex shape: one table per server, the name in the table path.
    #   [mcp_servers.github]
    # Skipped entirely when the file uses the array-of-tables form, because
    # there `[mcp_servers.auth]` is a SUB-TABLE of the preceding array entry,
    # not a server -- reading it as one invents an MCP server called "auth" on
    # every Vibe install that configures static auth.
    array_form = re.search(r"(?m)^\[\[mcp_servers\]\]", text) is not None
    for match in (
        () if array_form
        else re.finditer(r"(?m)^\[mcp_servers\.([^\]]+)\]", text)
    ):
        name = _asset_toml_table_server(match.group(1))
        if name and name not in seen:
            seen.add(name)
            items.append({"name": name, "path": str(path)})
    # Mistral Vibe Code shape: an ARRAY of tables, name as a key inside it.
    #   [[mcp_servers]]
    #   name = "github"
    # Matching only the Codex shape would report zero MCP servers for every
    # Vibe install that has them -- a silent asset-inventory gap, not an error.
    for match in re.finditer(
        r"(?ms)^\[\[mcp_servers\]\]\s*(.*?)(?=^\[|\Z)", text
    ):
        block = match.group(1)
        # Quote characters are kept OUT of the pattern and stripped after by
        # _asset_toml_table_server: this source is embedded verbatim into the
        # guard artifact, where a mixed-quote character class inside an
        # already-escaped string is a syntax error waiting to happen.
        name_match = re.search(r"(?m)^\s*name\s*=\s*(\S+)", block)
        if not name_match:
            continue
        name = _asset_toml_table_server(name_match.group(1).strip())
        if name and name not in seen:
            seen.add(name)
            items.append({"name": name, "path": str(path)})
    return items

def _asset_scan_mcp_from_toml(path):
    text = _skill_scan_read_text(path)
    if not text:
        return []
    if "[[mcp_servers]]" in text:
        return _asset_scan_mcp_array_from_toml(path)
    order = []
    disabled = set()
    for header, body in _asset_toml_tables(text):
        name, is_own_table = _asset_toml_child_key(header, "mcp_servers.")
        if not name:
            continue
        if name not in order:
            order.append(name)
        # `enabled` is only meaningful on the server's OWN table; a key of that
        # name inside [mcp_servers.x.env] is an environment variable.
        if is_own_table and _asset_toml_bool(body, "enabled") is False:
            disabled.add(name)
    return [
        {"name": name, "path": str(path)}
        for name in order
        if name not in disabled
    ]


def _asset_scan_plugins_from_toml(path):
    """Codex plugins, which live in config.toml as `[plugins."name@market"]`.

    Codex has no ~/.codex/plugins manifest tree, so the directory walk that
    serves every other agent found nothing and Codex reported 0 plugins on
    machines running eight of them.
    """
    text = _skill_scan_read_text(path)
    if not text:
        return []
    items = []
    seen = set()
    for header, body in _asset_toml_tables(text):
        name, is_own_table = _asset_toml_child_key(header, "plugins.")
        if not name or not is_own_table or name in seen:
            continue
        seen.add(name)
        if _asset_toml_bool(body, "enabled") is False:
            continue
        items.append({"name": name, "path": str(path)})
    return items


def _asset_plugin_roots_for_hook(hook_type, bases=None):
    home = Path.home()
    cwd = Path.cwd()
    relative_roots = {
        "cursor": (".cursor/plugins",),
        "claude-code": (".claude/plugins",),
        "codex": (".codex/plugins",),
        "copilot": (".copilot/plugins",),
        "github-copilot": (".copilot/plugins",),
        "windsurf": (".windsurf/plugins",),
        "antigravity": (".gemini/antigravity/plugins", ".antigravity/plugins"),
        "openclaw": (".openclaw/plugins",),
        "qwen-code": (".qwen/plugins",),
        "hermes": (".hermes/plugins",),

        "augment-code": (".augment/plugins",),
        "cline": (".cline/plugins", ".agents/plugins", "Documents/Cline/Plugins"),
        "kiro": (".kiro/powers",),
        "vibe-code": (".vibe/plugins",),
    }.get(_asset_scan_hook_key(hook_type), ())
    roots = []
    seen = set()
    for relative in relative_roots:
        for base in (bases if bases is not None else (home, cwd)):
            candidate = base / relative
            key = str(candidate)
            if key in seen:
                continue
            seen.add(key)
            if candidate.is_dir():
                roots.append(candidate)
    return roots


def _asset_scan_iter_plugin_manifests(root):
    found = []
    stack = [(root, 0)]
    visited = set()
    real_root = _skill_scan_real_root(root)
    skip = {"marketplaces", "cache"}
    manifests = {
        ".claude-plugin",
        ".codex-plugin",
        ".cursor-plugin",
        ".windsurf-plugin",
        ".copilot-plugin",
        ".openclaw-plugin",
    }
    while stack:
        if len(found) >= _ASSET_SCAN_MAX_FILES:
            _skill_scan_note_error("asset_limit", root, "file limit reached")
            break
        current, depth = stack.pop()
        if depth > _ASSET_SCAN_MAX_DEPTH:
            _skill_scan_note_error("asset_limit", root, "depth limit reached")
            continue
        try:
            if current.name.lower() in skip:
                continue
            real = str(current.resolve())
        except Exception as exc:
            _skill_scan_note_error("resolve", current, exc)
            continue
        if not _skill_scan_within(real, real_root):
            _skill_scan_note_error("outside_root", current, "symlink leaves the scan root")
            continue
        if real in visited:
            continue
        visited.add(real)
        try:
            entries = list(current.iterdir())
        except Exception as exc:
            _skill_scan_note_error("iterdir", current, exc)
            continue
        for entry in entries:
            if len(found) >= _ASSET_SCAN_MAX_FILES:
                break
            try:
                name_l = entry.name.lower()
                if name_l in skip:
                    continue
                if entry.is_dir():
                    stack.append((entry, depth + 1))
                elif name_l == "plugin.json" and entry.parent.name.lower() in manifests:
                    found.append(entry)
            except Exception as exc:
                _skill_scan_note_error("stat", entry, exc)
    return found


def _asset_scan_plugin_name(path):
    data = _asset_scan_json_object(path)
    name = str(data.get("name") or "").strip()
    if name:
        return name
    parent = path.parent
    if parent.name.lower().endswith("-plugin"):
        return parent.parent.name
    return path.parent.name


def _asset_scan_installed_plugins_file(path):
    data = _asset_scan_json_object(path)
    items = []
    plugins = data.get("plugins", data)
    if isinstance(plugins, dict):
        for key, value in plugins.items():
            name = str(key).split("@", 1)[0].strip()
            if isinstance(value, dict):
                if value.get("enabled") is False:
                    continue
                name = str(value.get("name") or name).strip()
            if name:
                items.append({"name": name, "path": str(path)})
    elif isinstance(plugins, list):
        for item in plugins:
            if isinstance(item, str) and item.strip():
                items.append({"name": item.strip(), "path": str(path)})
            elif isinstance(item, dict):
                name = str(item.get("name") or "").strip()
                if item.get("enabled") is False:
                    continue
                if name:
                    items.append({"name": name, "path": str(path)})
    return items


def _asset_rule_dir_relatives(hook_type):
    return {
        "cursor": (".cursor/rules",),
        "claude-code": (".claude/rules",),
        "codex": (".codex/rules",),
        "copilot": (".github/instructions", ".github/copilot"),
        "github-copilot": (".github/instructions", ".github/copilot"),
        "windsurf": (".windsurf/rules",),
        "antigravity": (".gemini/antigravity/rules", ".antigravity/rules"),
        "openclaw": (".openclaw/rules",),
        "qwen-code": (".qwen/rules",),
        "hermes": (".hermes/rules",),

        "augment-code": (".augment/rules",),
        "cline": (".clinerules", ".cline/rules", "Documents/Cline/Rules"),
        "kiro": (".kiro/steering",),
        "vibe-code": (".vibe/prompts",),
    }.get(_asset_scan_hook_key(hook_type), ())


def _asset_rule_named_relatives(hook_type):
    shared = ("CLAUDE.md", "AGENTS.md", "GEMINI.md")
    return {
        "cursor": shared + (".cursorrules", ".cursor/CLAUDE.md"),
        "claude-code": shared + (".claude/CLAUDE.md",),
        "codex": shared + (".codex/AGENTS.md",),
        "copilot": shared + (".github/copilot-instructions.md",),
        "github-copilot": shared + (".github/copilot-instructions.md",),
        "windsurf": shared + (".windsurfrules",),
        "antigravity": shared + ("GEMINI.md",),
        "openclaw": shared,
        # QWEN.md is Qwen Code's instruction file, its CLAUDE.md analogue.
        "qwen-code": shared + ("QWEN.md", ".qwen/QWEN.md"),
        # Hermes loads several files straight into the system prompt, so all
        # of them are instruction assets in the strongest sense: SOUL.md is
        # prompt slot #1 (agent identity), BOOT.md is executed verbatim as an
        # agent prompt on gateway startup, and the memories/ pair is replayed
        # into later turns. `.hermes.md` is its repo-level context file.
        "hermes": shared + (
            ".hermes/SOUL.md",
            ".hermes/BOOT.md",
            ".hermes/memories/MEMORY.md",
            ".hermes/memories/USER.md",
            ".hermes.md",
        ),

        "augment-code": shared + (
            ".augment-guidelines",
            ".augment/rules.md",
            ".augment/AGENTS.md",
        ),
        "cline": shared + (
            ".clinerules",
            ".clinerules.md",
            ".cline/AGENTS.md",
            ".agents/AGENTS.md",
        ),
        "kiro": shared + (
            ".kiro/steering/product.md",
            ".kiro/steering/tech.md",
            ".kiro/steering/structure.md",
        ),
        "vibe-code": shared + (".vibe/AGENTS.md",),
    }.get(_asset_scan_hook_key(hook_type), shared)


def _asset_scan_iter_rule_files(root):
    found = []
    stack = [(root, 0)]
    visited = set()
    real_root = _skill_scan_real_root(root)
    suffixes = {".md", ".mdc", ".markdown"}
    while stack:
        if len(found) >= _ASSET_SCAN_MAX_FILES:
            _skill_scan_note_error("asset_limit", root, "file limit reached")
            break
        current, depth = stack.pop()
        if depth > _ASSET_SCAN_MAX_DEPTH:
            _skill_scan_note_error("asset_limit", root, "depth limit reached")
            continue
        try:
            real = str(current.resolve())
        except Exception as exc:
            _skill_scan_note_error("resolve", current, exc)
            continue
        if not _skill_scan_within(real, real_root):
            _skill_scan_note_error("outside_root", current, "symlink leaves the scan root")
            continue
        if real in visited:
            continue
        visited.add(real)
        try:
            entries = list(current.iterdir())
        except Exception as exc:
            _skill_scan_note_error("iterdir", current, exc)
            continue
        for entry in entries:
            if len(found) >= _ASSET_SCAN_MAX_FILES:
                break
            try:
                if entry.is_dir():
                    stack.append((entry, depth + 1))
                elif entry.suffix.lower() in suffixes and entry.name.lower() != "skill.md":
                    found.append(entry)
            except Exception as exc:
                _skill_scan_note_error("stat", entry, exc)
    return found


def _asset_dedupe(items, by_name=False):
    out = []
    seen = set()
    for item in items:
        name = str((item or {}).get("name") or "").strip()
        path = str((item or {}).get("path") or "").strip()
        if not name and not path:
            continue
        key = name.lower() if by_name and name else (name.lower(), path)
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name or path.rsplit("/", 1)[-1], "path": path})
        if len(out) >= _ASSET_SCAN_MAX_FILES:
            break
    return out


def _asset_read_mcp_file(path, container, kind):
    if kind == "toml":
        return _asset_scan_mcp_from_toml(path)
    if kind == "yaml":
        return _asset_scan_mcp_from_yaml(path, container)
    if kind == "claude-json":
        return _asset_scan_mcp_from_claude_json(path, container)
    return _asset_scan_mcp_from_json(path, container)


def _scan_installed_agent_mcps(hook_type, bases=None, editor=True):
    candidates = []
    for relative, container, kind in _asset_scan_mcp_specs(hook_type):
        for base in (bases if bases is not None else (Path.home(), Path.cwd())):
            candidates.append((base / relative, container, kind))
    if editor:
        candidates.extend(_asset_scan_mcp_editor_specs(hook_type))
    items = []
    seen_files = set()
    for path, container, kind in candidates:
        key = str(path)
        if key in seen_files:
            continue
        seen_files.add(key)
        try:
            if not path.is_file():
                continue
        except Exception as exc:
            _skill_scan_note_error("mcp_stat", path, exc)
            continue
        items.extend(_asset_read_mcp_file(path, container, kind))
    return _asset_dedupe(items, by_name=True)


def _scan_installed_agent_plugins(hook_type, bases=None):
    items = []
    seen_paths = set()
    if _asset_scan_hook_key(hook_type) == "claude-code" and (bases is None or Path.home() in bases):
        installed = Path.home() / ".claude" / "plugins" / "installed_plugins.json"
        if installed.is_file():
            items.extend(_asset_scan_installed_plugins_file(installed))
    if _asset_scan_hook_key(hook_type) == "codex":
        for base in (bases if bases is not None else (Path.home(), Path.cwd())):
            config = base / ".codex" / "config.toml"
            if config.is_file():
                items.extend(_asset_scan_plugins_from_toml(config))
    for root in _asset_plugin_roots_for_hook(hook_type, bases=bases):
        for manifest in _asset_scan_iter_plugin_manifests(root):
            key = str(manifest)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            items.append({"name": _asset_scan_plugin_name(manifest), "path": key})
    return _asset_dedupe(items, by_name=True)


def _scan_installed_agent_rules(hook_type, bases=None):
    items = []
    seen_paths = set()
    for relative in _asset_rule_named_relatives(hook_type):
        for base in (bases if bases is not None else (Path.home(), Path.cwd())):
            path = base / relative
            key = str(path)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            if path.is_file():
                items.append({"name": path.name, "path": key})
    for relative in _asset_rule_dir_relatives(hook_type):
        for base in (bases if bases is not None else (Path.home(), Path.cwd())):
            root = base / relative
            if not root.is_dir():
                continue
            for path in _asset_scan_iter_rule_files(root):
                key = str(path)
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                items.append({"name": path.name, "path": key})
    return _asset_dedupe(items)


def _scan_installed_agent_skills(hook_type=None, *, session_id=""):
    import datetime as _dt

    _skill_scan_prepare_context()
    session_id = str(session_id or "")
    if (
        _SKILL_SCAN_CACHE.get("session_id") == session_id
        and isinstance(_SKILL_SCAN_CACHE.get("inventory"), dict)
    ):
        return dict(_SKILL_SCAN_CACHE["inventory"])

    cached = _skill_scan_cache_load(session_id)
    if cached is not None and isinstance(cached.get("inventory"), dict):
        _skill_scan_cache_hydrate(session_id, cached)
        return dict(cached["inventory"])

    errors_before = _SKILL_SCAN_ERROR_COUNT
    skills = []
    seen_paths = set()
    for root in _skill_scan_roots_for_hook(hook_type):
        for skill_md in _skill_scan_iter_skill_files(root):
            key = str(skill_md)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            text = _skill_scan_read_text(skill_md)
            if not text.strip():
                continue
            findings, sha, trust_status, risk_score = _skill_scan_findings(
                text,
                file_name=skill_md.name,
            )
            skills.append({
                "name": _skill_scan_frontmatter_name(text),
                "path": key,
                "content_sha256": sha,
                "trust_status": trust_status,
                "risk_score": risk_score,
                "findings": findings,
            })

    worst = "unverified"
    rank = {"verified": 0, "pending": 1, "unverified": 2, "blocked": 3}
    if skills:
        worst = max((str(item.get("trust_status") or "unverified") for item in skills), key=lambda value: rank.get(value, 2))
    inventory = {
        "skills": skills,
        "scan_complete": _SKILL_SCAN_ERROR_COUNT == errors_before,
        "worst_trust_status": worst,
        "scanned_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "hook_type": str(hook_type or HOOK_TYPE),
    }
    _SKILL_SCAN_CACHE["session_id"] = session_id
    _SKILL_SCAN_CACHE["inventory"] = dict(inventory)
    _skill_scan_cache_store(
        session_id,
        inventory,
        _SKILL_SCAN_CACHE.get("asset_inventory"),
    )
    return inventory


def _scan_agent_asset_inventory(hook_type=None, scanned_at=None, bases=None, editor=True):
    """One agent's MCP / plugin / rule inventory. Pure: no cache, no I/O reuse.

    Deliberately not cached. _scan_all_agent_assets is the single writer of the
    shared on-disk cache; a second caching entry point wrote the same file with
    `asset_inventories` omitted, which silently dropped the whole-device
    snapshot the next invocation would have reused.
    """
    import datetime as _dt

    errors_before = _SKILL_SCAN_ERROR_COUNT
    mcps = _scan_installed_agent_mcps(hook_type, bases=bases, editor=editor)
    plugins = _scan_installed_agent_plugins(hook_type, bases=bases)
    rules = _scan_installed_agent_rules(hook_type, bases=bases)
    return {
        "hook_type": str(hook_type or HOOK_TYPE),
        "scanned_at": scanned_at
        or _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "scan_complete": _SKILL_SCAN_ERROR_COUNT == errors_before,
        "mcps": mcps,
        "plugins": plugins,
        "rules": rules,
        "mcp_count": len(mcps),
        "plugin_count": len(plugins),
        "rule_count": len(rules),
    }


# Every agent this scanner knows how to inventory. Order is the ATTRIBUTION
# order for assets more than one agent can see (see _asset_claim_unseen), so it
# is fixed and shared with the install-time caller rather than derived from
# whichever agent happens to be running.
_ASSET_SCAN_HOOK_TYPES = (
    "cursor",
    "claude-code",
    "codex",
    "copilot",
    "windsurf",
    "antigravity",
    "openclaw",
    "qwen-code",
    "hermes",
    "augment-code",
    "vibe-code",
    "kiro",
    "cline",
)

def _asset_inventory_has_assets(inventory):
    for key in ("mcp_count", "plugin_count", "rule_count"):
        try:
            if int(inventory.get(key) or 0) > 0:
                return True
        except Exception:
            continue
    return False


def _scan_all_agent_assets(session_id="", hook_types=None, include_empty=False):
    """Report separately replaceable home and current-workspace observations.

    Other workspaces remain last-known snapshots on the server. Failed scopes
    are explicit, so neither a read error nor an omitted agent proves removal.
    Per-agent associations stay intact; the server deduplicates device totals.
    """
    import datetime as _dt
    import hashlib

    _skill_scan_prepare_context()
    session_id = str(session_id or "")
    cacheable = hook_types is None and include_empty
    cached = _SKILL_SCAN_CACHE.get("asset_inventories")
    if cacheable and _SKILL_SCAN_CACHE.get("session_id") == session_id and isinstance(cached, list):
        return [dict(item) for item in cached]
    stored = _skill_scan_cache_load(session_id) if cacheable else None
    if stored is not None and isinstance(stored.get("asset_inventories"), list):
        _skill_scan_cache_hydrate(session_id, stored)
        return [dict(item) for item in stored["asset_inventories"] if isinstance(item, dict)]
    scanned_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
    home, cwd = Path.home(), Path.cwd()
    roots = [("home", home, True)]
    if cwd != home:
        scope = "workspace:" + hashlib.sha256(str(cwd).encode()).hexdigest()
        roots.append((scope, cwd, False))
    snapshots = []
    for hook in dict.fromkeys(hook_types or _ASSET_SCAN_HOOK_TYPES):
        scopes = []
        for scope_key, base, editor in roots:
            try:
                inventory = _scan_agent_asset_inventory(hook, scanned_at, bases=(base,), editor=editor)
            except Exception as exc:
                _skill_scan_note_error("asset_scan_hook", hook, exc)
                inventory = {"scan_complete": False, "scanned_at": scanned_at}
            inventory["scope_key"] = scope_key
            scopes.append(inventory)
        entry = {"hook_type": hook, "scanned_at": scanned_at, "scan_scopes": scopes,
                 "scan_complete": all(scope["scan_complete"] for scope in scopes)}
        for kind in ("mcps", "plugins", "rules"):
            entry[kind] = _asset_dedupe([item for scope in scopes for item in scope.get(kind, [])])
            entry[kind[:-1] + "_count"] = len(entry[kind])
        if include_empty or _asset_inventory_has_assets(entry) or not entry["scan_complete"]:
            snapshots.append(entry)
    if cacheable:
        _SKILL_SCAN_CACHE["session_id"] = session_id
        _SKILL_SCAN_CACHE["asset_inventories"] = [dict(item) for item in snapshots]
        _skill_scan_cache_store(session_id, _SKILL_SCAN_CACHE.get("inventory"), None, snapshots)
    return snapshots


def _merge_skill_inventory(payload, hook_type=None, session_id=""):
    global _SKILL_SCAN_ERROR_COUNT
    session_id = session_id or str((payload or {}).get("session_id") or "")
    # Automatic skill risk scanning is retired. Keep this function name for
    # rendered-adapter compatibility, but only refresh MCP/plugin/rule assets.
    try:
        running = str(hook_type or HOOK_TYPE).strip().lower()
        # The device, not just this process. Every agent's MCP / plugin / rule
        # config sits on disk and is readable right now, so the agent that
        # happens to be running refreshes them all. Without this, an agent that
        # last ran days ago had no snapshot at all and the page showed its row
        # as 0 -- and the device total, being the sum of those rows, was wrong
        # by everything the quiet agents actually have installed.
        inventories = _scan_all_agent_assets(
            session_id=session_id, include_empty=True
        )
        mine = None
        for item in inventories:
            if str(item.get("hook_type") or "").strip().lower() == running:
                mine = item
                break
        payload["asset_inventories"] = inventories
        # Old servers cannot retain scope/failure status. Only send their
        # fallback snapshot after every requested scope completed successfully.
        if mine is not None and mine["scan_complete"]:
            payload["asset_inventory"] = mine
    except Exception as exc:
        _record_capture_failure(
            str(hook_type or HOOK_TYPE),
            "asset_scan",
            exc,
            payload or {},
        )
    # Inner read/walk failures are collected rather than raised so a single
    # unreadable asset cannot abort the inventory — but they must still be
    # observable, per the no-silent-failure rule for hook code.
    if _SKILL_SCAN_ERRORS:
        try:
            _record_capture_failure(
                str(hook_type or HOOK_TYPE),
                "asset_scan_partial",
                Exception("asset inventory scan completed with %d error(s) (up to 20 details recorded)" % _SKILL_SCAN_ERROR_COUNT),
                {"asset_scan_errors": list(_SKILL_SCAN_ERRORS)},
            )
        except Exception:
            pass
        del _SKILL_SCAN_ERRORS[:]
        _SKILL_SCAN_ERROR_COUNT = 0
    return payload



def _tenetx_developer_message(result, default="Blocked by policy"):
    """Return the best developer-facing TenetX notice for Codex.

    New TenetX servers send a structured agent_notice with a Codex-specific
    surface message. Older servers only send reason, so keep that fallback.
    """
    if not isinstance(result, dict):
        return default
    notice = result.get("agent_notice")
    if isinstance(notice, dict):
        surfaces = notice.get("surfaces")
        if isinstance(surfaces, dict):
            for surface in (
                "codex:" + CLIENT_SURFACE,
                "codex",
                CLIENT_SURFACE,
                "default",
            ):
                surface_notice = surfaces.get(surface)
                if isinstance(surface_notice, dict):
                    value = surface_notice.get("message")
                    if isinstance(value, str) and value.strip():
                        return value.strip()
        value = notice.get("message")
        if isinstance(value, str) and value.strip():
            return value.strip()
    for key in ("developer_message", "message", "reason"):
        value = result.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default


def _tenetx_prefixed_message(message):
    text = str(message or "").strip()
    if not text:
        return "🛡 TenetX Guard: Blocked by security policy"
    lower = text.lower()
    if (
        text.startswith("🛡")
        or lower.startswith("tenetx:")
        or lower.startswith("tenetx guard:")
        or lower.startswith("tenetx guard ")
    ):
        return text
    return "🛡 TenetX Guard: " + text


def _pretooluse_block_payload(message):
    """Return both current Codex block text and legacy PreToolUse deny fields."""
    reason = _tenetx_prefixed_message(message)
    return {
        "decision": "block",
        "reason": reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
    }


def _pretooluse_allow_rewrite_payload(updated_input):
    """Return the current Codex schema for an authoritative input rewrite."""
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated_input,
        }
    }


def _codex_work_item_required_message():
    return "Reply `regular`/`no ticket` or a Jira key like PROJ-123, then retry the request."


def _codex_ask_converted_to_block_message(result, fallback_detail="", post_execution=False):
    """Return a short ASK notice for Codex paths that must fail-safe deny."""
    if _is_work_item_required_result(result):
        return _tenetx_prefixed_message(_codex_work_item_required_message())
    text = ""
    if isinstance(result, dict):
        notice = result.get("agent_notice")
        if isinstance(notice, dict):
            surfaces = notice.get("surfaces")
            if isinstance(surfaces, dict):
                for surface in ("codex:" + CLIENT_SURFACE, "codex"):
                    surface_notice = surfaces.get(surface)
                    if isinstance(surface_notice, dict):
                        preferred_key = (
                            "post_execution_message" if post_execution else "pre_execution_message"
                        )
                        value = surface_notice.get(preferred_key)
                        if isinstance(value, str) and value.strip():
                            text = value.strip()
                            break
    if not text:
        text = _tenetx_developer_message(result, fallback_detail).strip()
    lower = text.lower()
    noisy_markers = (
        "review needed:",
        "why:",
        "evidence:",
        "safer path:",
        "audit id",
        "cannot pause for approval",
        "does not yet support hook approval prompts",
    )
    if (
        not text
        or "\n" in text
        or lower.startswith("tenetx guard: action blocked")
        or lower.startswith("tenetx guard action blocked")
        or any(marker in lower for marker in noisy_markers)
    ):
        return "🛡 TenetX Guard: approval required"
    return _tenetx_prefixed_message(text)


def handle_pre_tool_use(hook_input, tool_name, tool_input, session_id=""):
    """PreToolUse: enforce policy first, then mask allowed readable input."""
    if not isinstance(tool_input, dict):
        tool_input = {}

    tool_name = normalize_tool_name(tool_name)
    tool_input = normalize_tool_input(tool_name, tool_input, tool_input.get("raw_tool_name"))
    guard_tamper = _gsp_local_integrity_reason(tool_name, tool_input)

    if tool_name not in ("Bash", "CodexExec", "Browser", "MCP", "Read", "Write", "Edit"):
        sys.exit(0)

    # A guard-integrity invariant remains locally authoritative, but the
    # server still receives the attempt when reachable for canonical V3 audit.
    if guard_tamper:
        hook_input = dict(hook_input)
        hook_input["tenetx_local_enforcement"] = {
            "authority": "local_integrity_invariant",
            "invariant_code": _GSP_INVARIANT_CODE,
            "detector": guard_tamper,
        }

    fail_open = should_fail_open(tool_name, tool_input)

    # Standard API check
    vmcp_correlation_id = get_vmcp_correlation_id(hook_input)

    payload = {
        "client_surface": CLIENT_SURFACE,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "hook_event_name": "PreToolUse",
        "tool_call_id": vmcp_correlation_id,
        "tool_use_id": vmcp_correlation_id,
        "request_id": vmcp_correlation_id,
        "id": vmcp_correlation_id,
        "trace_id": vmcp_correlation_id,
        "session_id": session_id,
        "prompt_session_id": session_id,
        "agent_id": socket.gethostname(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "user_email": os.environ.get("TENETX_USER_EMAIL", ""),
        "hook_type": "request",
        "local_enforcement": hook_input.get("tenetx_local_enforcement") or {},
        "metadata": {
            "model": hook_input.get("model", ""),
            "turn_id": hook_input.get("turn_id", ""),
            "permission_mode": hook_input.get("permission_mode", ""),
            "cwd": hook_input.get("cwd", ""),
            "hook_event_name": "PreToolUse",
            "raw_tool_name": tool_input.get("raw_tool_name", ""),
        },
    }

    _merge_skill_inventory(payload, session_id=session_id)

    url = TENETX_URL + "/api/vmcp/" + TENETX_ORG + "/codex/check"

    try:
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if VMCP_TOKEN:
            headers["Authorization"] = "Bearer " + VMCP_TOKEN
        req = urllib.request.Request(
            url,
            data=_json_payload(payload, urlparse(url).path),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT) as response:
            result = json.load(response)
        result = validate_policy_response(result)
        debug_log("check_request_ok")
        write_posture_marker(POSTURE_HEALTHY_VALUE, "tenetx_api_verified", "/codex/check")

    except Exception as e:
        debug_log("check_request_error=" + type(e).__name__ + " " + str(e)[:160])
        write_posture_marker(POSTURE_UNHEALTHY_VALUE, "tenetx_api_error:" + type(e).__name__, "/codex/check")
        if guard_tamper:
            debug_log(
                "guard_self_protection_block="
                + guard_tamper
                + " server_decision=unavailable"
            )
            print(json.dumps(_pretooluse_block_payload(_gsp_local_block_message())))
            sys.exit(0)
        if fail_open:
            sys.exit(0)
        else:
            reason = _signin_remediation(VMCP_TOKEN) or (
                "High-risk operation blocked (API error: " + str(e) + ")"
            )
            print(json.dumps(_pretooluse_block_payload(
                reason
            )))
            sys.exit(0)

    decision = result.get("decision", "allow")
    if guard_tamper:
        debug_log(
            "guard_self_protection_block="
            + guard_tamper
            + " server_decision="
            + str(decision)
        )
        print(json.dumps(_pretooluse_block_payload(_gsp_local_block_message())))
        write_posture_marker(
            POSTURE_UNHEALTHY_VALUE,
            "guard_self_protection:" + guard_tamper,
            "/codex/check",
        )
        sys.exit(0)

    if decision == "block":
        reason = _tenetx_developer_message(result, "Blocked by security policy")
        print(json.dumps(_pretooluse_block_payload(reason)))
        sys.exit(0)

    if decision == "ask":
        if _codex_pretool_ask_can_defer(result, tool_name, tool_input):
            remember_pending_ask(hook_input, tool_name, session_id, vmcp_correlation_id, result)
            debug_log("pretooluse_ask_deferred_to_codex_native_prompt")
            sys.exit(0)
        resolve_unsupported_ask(
            hook_input,
            result,
            tool_name,
            tool_input,
            session_id,
            vmcp_correlation_id,
            "codex_pretool_ask_unsupported",
        )
        reason = _codex_ask_converted_to_block_message(result, "Approval required by security policy")
        print(json.dumps(_pretooluse_block_payload(reason)))
        sys.exit(0)

    # Response scanning is deliberately after the latency-sensitive /check
    # round trip, so policy enforcement is never queued behind DLP I/O.
    masked_rewrite = None
    if tool_name == "Read":
        masked_rewrite = _handle_read_tool(hook_input, tool_input)
    elif tool_name == "Bash":
        masked_rewrite = _handle_bash_read(hook_input, tool_input)

    modified_input = result.get("modified_input")
    if isinstance(modified_input, dict):
        rewritten = dict(
            ((masked_rewrite or {}).get("hookSpecificOutput") or {}).get(
                "updatedInput"
            )
            or tool_input
        )
        rewritten.update(modified_input)
        masked_rewrite = _pretooluse_allow_rewrite_payload(rewritten)
    if masked_rewrite:
        print(json.dumps(masked_rewrite))

    sys.exit(0)


def handle_permission_request(hook_input, tool_name, tool_input, session_id=""):
    """PermissionRequest: pre-answer Codex approval prompts with TenetX policy."""
    if not isinstance(tool_input, dict):
        tool_input = {}

    tool_name = normalize_tool_name(tool_name)
    tool_input = normalize_tool_input(tool_name, tool_input, tool_input.get("raw_tool_name"))

    if tool_name not in ("Bash", "CodexExec", "MCP", "Write", "Edit"):
        sys.exit(0)

    fail_open = should_fail_open(tool_name, tool_input)

    vmcp_correlation_id = get_vmcp_correlation_id(hook_input)
    description = tool_input.get("description") or hook_input.get("description") or ""

    payload = {
        "client_surface": CLIENT_SURFACE,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "hook_event_name": "PermissionRequest",
        "tool_call_id": vmcp_correlation_id,
        "tool_use_id": vmcp_correlation_id,
        "request_id": vmcp_correlation_id,
        "id": vmcp_correlation_id,
        "trace_id": vmcp_correlation_id,
        "session_id": session_id,
        "prompt_session_id": session_id,
        "agent_id": socket.gethostname(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "user_email": os.environ.get("TENETX_USER_EMAIL", ""),
        "hook_type": "request",
        "metadata": {
            "model": hook_input.get("model", ""),
            "turn_id": hook_input.get("turn_id", ""),
            "permission_mode": hook_input.get("permission_mode", ""),
            "cwd": hook_input.get("cwd", ""),
            "hook_event_name": "PermissionRequest",
            "raw_tool_name": tool_input.get("raw_tool_name", ""),
            "approval_description": description,
        },
    }

    _merge_skill_inventory(payload, session_id=session_id)

    url = TENETX_URL + "/api/vmcp/" + TENETX_ORG + "/codex/check"

    try:
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
        if VMCP_TOKEN:
            headers["Authorization"] = "Bearer " + VMCP_TOKEN
        req = urllib.request.Request(
            url,
            data=_json_payload(payload, urlparse(url).path),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CONTEXT) as response:
            result = json.load(response)
        result = validate_policy_response(result)
        debug_log("permission_request_ok")
        write_posture_marker(POSTURE_HEALTHY_VALUE, "tenetx_api_verified", "/codex/check")

    except Exception as e:
        debug_log("permission_request_error=" + type(e).__name__ + " " + str(e)[:160])
        write_posture_marker(POSTURE_UNHEALTHY_VALUE, "tenetx_api_error:" + type(e).__name__, "/codex/check")
        if fail_open:
            sys.exit(0)
        reason = _signin_remediation(VMCP_TOKEN) or (
            "🛡 TenetX Guard: High-risk operation blocked (API error: " + str(e) + ")"
        )
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": reason,
                },
            }
        }))
        sys.exit(0)

    decision = result.get("decision", "allow")
    if decision == "allow":
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "allow"},
            }
        }))
        sys.exit(0)

    if decision == "ask" and PERMISSION_ASK_MODE == "defer":
        remember_pending_ask(hook_input, tool_name, session_id, vmcp_correlation_id, result)
        _start_skip_feedback_watcher(session_id)
        debug_log("permission_request_ask_deferred_to_codex_native_prompt")
        sys.exit(0)

    if decision in ("block", "ask"):
        reason = _tenetx_developer_message(result, "Blocked by security policy")
        if decision == "ask":
            resolve_unsupported_ask(
                hook_input,
                result,
                tool_name,
                tool_input,
                session_id,
                vmcp_correlation_id,
                "codex_permission_ask_unsupported",
            )
            reason = _codex_ask_converted_to_block_message(result, "Approval required by security policy")
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": _tenetx_prefixed_message(reason),
                },
            }
        }))
        sys.exit(0)

    sys.exit(0)


def handle_post_tool_use(hook_input, tool_name, tool_input, session_id):
    """PostToolUse: scan tool output for sensitive data and withhold unsafe results."""
    if not isinstance(tool_input, dict):
        tool_input = {}

    tool_name = normalize_tool_name(tool_name)
    tool_input = normalize_tool_input(tool_name, tool_input, tool_input.get("raw_tool_name"))

    tool_response = hook_input.get("tool_response", {}) or {}
    vmcp_correlation_id = get_vmcp_correlation_id(hook_input)
    pending_ask = load_pending_ask(vmcp_correlation_id, session_id, tool_name)
    feedback_hook_input = dict(hook_input)
    if pending_ask and pending_ask.get("decision_id") and not feedback_hook_input.get("decision_id"):
        feedback_hook_input["decision_id"] = pending_ask.get("decision_id")
    feedback_result = send_decision_feedback(
        feedback_hook_input,
        tool_name,
        session_id,
        vmcp_correlation_id,
    )
    if feedback_result is not None:
        forget_pending_ask(vmcp_correlation_id, session_id, tool_name)
    feedback_context = direct_feedback_context(feedback_result)

    # Extract content from various response shapes
    content = None
    if isinstance(tool_response, str):
        content = tool_response
    elif isinstance(tool_response, dict):
        if isinstance(tool_response.get("content"), str):
            content = tool_response["content"]
        else:
            stdout = tool_response.get("stdout") or ""
            stderr = tool_response.get("stderr") or ""
            if isinstance(stdout, str) and isinstance(stderr, str):
                combined = (stdout + ("\n" if stdout and stderr else "") + stderr).strip()
                content = combined

    if not isinstance(content, str):
        if feedback_context:
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": feedback_context,
                }
            }))
        sys.exit(0)

    if len(content.encode("utf-8")) > MAX_RESPONSE_SCAN_BYTES:
        print(json.dumps({
            "decision": "block",
            "reason": "🛡 TenetX Guard withheld Bash output because it exceeded the response scan limit.",
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "Re-run with a narrower command or approved export path.",
            },
        }))
        sys.exit(0)

    payload = {
        "client_surface": CLIENT_SURFACE,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_output": content,
        "hook_event_name": "PostToolUse",
        "tool_call_id": vmcp_correlation_id,
        "tool_use_id": vmcp_correlation_id,
        "request_id": vmcp_correlation_id,
        "id": vmcp_correlation_id,
        "trace_id": vmcp_correlation_id,
        "session_id": session_id,
        "prompt_session_id": session_id,
        "agent_id": socket.gethostname(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "user_email": os.environ.get("TENETX_USER_EMAIL", ""),
        "hook_type": "response",
        "metadata": {
            "model": hook_input.get("model", ""),
            "turn_id": hook_input.get("turn_id", ""),
            "permission_mode": hook_input.get("permission_mode", ""),
            "hook_event_name": "PostToolUse",
            "raw_tool_name": tool_input.get("raw_tool_name", ""),
        },
    }

    url = TENETX_URL + "/api/vmcp/" + TENETX_ORG + "/codex/check-response"

    try:
        timeout = _response_http_timeout()
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT, "X-TenetX-Response-Timeout-Ms": str(int(timeout * 1000))}
        if VMCP_TOKEN:
            headers["Authorization"] = "Bearer " + VMCP_TOKEN
        req = urllib.request.Request(
            url,
            data=_json_payload(payload, urlparse(url).path),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CONTEXT) as response:
            result = json.load(response)
        debug_log("post_tool_use_ok")
        write_posture_marker(POSTURE_HEALTHY_VALUE, "tenetx_api_verified", "/codex/check-response")
    except Exception as e:
        debug_log("post_tool_use_error=" + type(e).__name__ + " " + str(e)[:160])
        write_posture_marker(POSTURE_UNHEALTHY_VALUE, "tenetx_api_error:" + type(e).__name__, "/codex/check-response")
        if feedback_context:
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": feedback_context,
                }
            }))
        sys.exit(0)

    if result.get("decision") == "block":
        reason = _tenetx_developer_message(result, "Blocked by security policy")
        print(json.dumps({
            "decision": "block",
            "reason": _tenetx_prefixed_message(reason),
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "🛡 TenetX Guard withheld the tool output from Codex.",
            },
        }))
        sys.exit(0)

    if result.get("decision") == "ask":
        resolve_unsupported_ask(
            hook_input,
            result,
            tool_name,
            tool_input,
            session_id,
            vmcp_correlation_id,
            "codex_posttool_ask_unsupported",
        )
        reason = _codex_ask_converted_to_block_message(
            result,
            "Approval required after the action ran; TenetX withheld the result",
            post_execution=True,
        )
        print(json.dumps({
            "decision": "block",
            "reason": reason,
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": "🛡 TenetX Guard withheld the tool output pending approval.",
            },
        }))
        sys.exit(0)

    if result.get("modified"):
        pii_found = result.get("pii_found", []) or []
        modified_by = result.get("modified_by")
        context_msg = "🛡 TenetX Guard withheld modified tool output"
        if pii_found:
            context_msg = context_msg + " (PII masked: " + ", ".join(pii_found) + ")"
        if modified_by:
            context_msg = context_msg + " by " + modified_by

        print(json.dumps({
            "decision": "block",
            "reason": (
                "🛡 TenetX Guard withheld modified tool output because Codex does not yet support hook output replacement."
            ),
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": context_msg,
            },
        }))
        sys.exit(0)

    if feedback_context:
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": feedback_context,
            }
        }))

    sys.exit(0)


def _is_codex_system_prompt(text):
    """Detect Codex internal system prompts that are not user content."""
    prefixes = (
        "You are a helpful assistant. You will be presented with a user prompt, and your job is to provide a short title",
        "You are a helpful assistant. You will be presented with a user prompt",
    )
    stripped = text.strip()
    return any(stripped.startswith(prefix) for prefix in prefixes)


def _extract_codex_human_prompt(text):
    """Extract the human tail from Codex's composite UserPromptSubmit payload."""
    if not isinstance(text, str):
        return None
    marker_re = re.compile(
        r"(?im)^\s*(?:#{1,6}\s*)?my request(?:\s+for\s+codex)?\s*:\s*"
    )
    matches = list(marker_re.finditer(text))
    if matches:
        return text[matches[-1].end():].strip() or None
    stripped = text.strip()
    head = stripped[:300].lower()
    injected_prefixes = (
        "<recommended_plugins>", "<environment_context>", "<user_instructions>",
        "<permissions instructions>", "<skills_instructions>", "<apps_instructions>",
        "<plugins_instructions>", "<app-context>", "<appshot", "<turn_aborted",
        "<turn_context", "<codex_internal_context",
        "# applications mentioned by the user", "# agents.md instructions",
    )
    if not stripped or any(head.startswith(prefix) for prefix in injected_prefixes):
        return None
    return stripped


def handle_prompt_submit(hook_input, session_id):
    """DLP check on user prompt before it reaches the LLM."""
    prompt = hook_input.get("prompt") or hook_input.get("user_prompt") or hook_input.get("input") or ""
    if not isinstance(prompt, str) or not prompt.strip():
        sys.exit(0)

    # Skip Codex internal system prompts (e.g., title generation) — not user content
    if _is_codex_system_prompt(prompt):
        debug_log("skipping_codex_system_prompt")
        sys.exit(0)

    prompt = _extract_codex_human_prompt(prompt)
    if not prompt:
        debug_log("skipping_codex_injected_context")
        sys.exit(0)

    if len(prompt) > 8000:
        prompt = prompt[:8000]

    vmcp_correlation_id = get_vmcp_correlation_id(hook_input)

    result = _handle_prompt_work_item_reply(hook_input, session_id, prompt, vmcp_correlation_id)
    if result is None:
        result = send_codex_check(
            hook_input,
            "UserPromptSubmit",
            {"prompt": prompt},
            session_id,
            vmcp_correlation_id,
            hook_event_name="UserPromptSubmit",
        )
    if not isinstance(result, dict):
        sys.exit(0)

    decision = result.get("decision", "allow")
    if decision == "allow":
        modified_input = result.get("modified_input")
        modified_prompt = (
            modified_input.get("prompt")
            if isinstance(modified_input, dict)
            else None
        )
        if isinstance(modified_prompt, str) and modified_prompt != prompt:
            reason = (
                "🛡 TenetX Guard did not send this prompt to the coding agent "
                "because it contained sensitive data. Remove or redact the "
                "sensitive value, then submit the prompt again."
            )
            print(json.dumps({"decision": "block", "reason": reason}))
            sys.exit(0)
        forget_prompt_work_item_ask(session_id)
        sys.exit(0)
    if decision == "block":
        if _is_work_item_required_result(result):
            remember_prompt_work_item_ask(session_id, result)
            reason = _codex_work_item_required_message()
        else:
            reason = _tenetx_developer_message(result, "Blocked by security policy")
        print(json.dumps({
            "decision": "block",
            "reason": _tenetx_prefixed_message(reason),
        }))
        sys.exit(0)
    if decision == "ask":
        if _is_work_item_required_result(result):
            remember_prompt_work_item_ask(session_id, result)
        else:
            resolve_unsupported_ask(
                hook_input,
                result,
                "UserPromptSubmit",
                {"prompt": prompt},
                session_id,
                vmcp_correlation_id,
                "codex_prompt_ask_unsupported",
            )
        reason = _codex_ask_converted_to_block_message(result, "Approval required by security policy")
        print(json.dumps({
            "decision": "block",
            "reason": reason,
        }))
        sys.exit(0)

    sys.exit(0)


# ---------------------------------------------------------------------------
# Input rewrite helpers. Current Codex PreToolUse supports authoritative
# `permissionDecision: allow` plus `updatedInput`; PostToolUse intentionally
# uses block feedback to replace a sensitive result because direct output
# replacement fields remain unsupported.
# ---------------------------------------------------------------------------

READ_COMMANDS = {
    "cat", "head", "tail", "grep", "awk", "sed",
    "sort", "cut", "wc", "diff", "uniq", "tr",
    "strings", "base64", "xxd", "hexdump",
}

SCANNABLE_EXTENSIONS = {
    ".txt", ".md", ".rst", ".csv", ".tsv",
    ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".properties",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".rs",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".php", ".swift", ".kt", ".scala",
    ".r", ".R", ".pl", ".pm", ".lua", ".ex", ".exs", ".erl",
    ".html", ".htm", ".css", ".xml", ".xhtml",
    ".sh", ".bash", ".zsh", ".fish",
    ".sql", ".log",
}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


def _handle_read_tool(hook_input, tool_input):
    """Handle Read tool: read file locally, mask PII, swap path."""
    if not isinstance(tool_input, dict):
        return None
    file_path = tool_input.get("file_path", "")
    if not file_path or not isinstance(file_path, str):
        return None
    filepath = _resolve_file_path(file_path, hook_input, tool_input)
    tmppath = _mask_file_via_api(filepath, hook_input, tool_input, tool_name="Read")
    if not tmppath:
        return None
    debug_log("read_tool_masked file=" + filepath + " tmp=" + tmppath)
    updated = dict(tool_input)
    updated["file_path"] = tmppath
    return _pretooluse_allow_rewrite_payload(updated)


def _handle_bash_read(hook_input, tool_input):
    """Handle Bash tool: intercept read commands (cat, head, grep), mask PII."""
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command", "")
    if not command or not isinstance(command, str):
        return None

    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts:
        return None

    cmd_name = parts[0]

    # python3 -c "open('file').read()"
    if cmd_name in ("python3", "python") and "-c" in parts:
        return _handle_python_inline(command, hook_input, tool_input)

    # diff: two files
    if cmd_name == "diff":
        return _handle_diff(parts, hook_input, tool_input)

    # sed: only read-only (no -i flag)
    if cmd_name == "sed":
        if "-i" in parts:
            return None
        return _handle_simple_read(parts, hook_input, tool_input)

    # All other known read commands
    if cmd_name in READ_COMMANDS:
        return _handle_simple_read(parts, hook_input, tool_input)

    return None


def _resolve_file_path(filename, hook_input, tool_input):
    """Resolve a filename to an absolute path."""
    if os.path.isabs(filename):
        return filename
    cwd = ""
    if isinstance(tool_input, dict):
        cwd = tool_input.get("working_directory", "") or ""
    if not cwd:
        cwd = hook_input.get("cwd", "") or os.getcwd()
    return os.path.join(cwd, filename)


def _should_scan(filepath):
    """Check if file is scannable: known text extension and under size cap."""
    _, ext = os.path.splitext(filepath)
    if ext.lower() not in SCANNABLE_EXTENSIONS:
        return False
    try:
        if os.path.getsize(filepath) > MAX_FILE_SIZE:
            return False
    except OSError:
        return False
    return True


def _read_file_content(filepath):
    """Read file content, return None on error."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def _send_to_tenetx(content, file_path, hook_input, tool_name="Bash"):
    """Send file content to TenetX check-response API for PII masking."""
    session_id = get_session_id(hook_input)
    vmcp_correlation_id = get_vmcp_correlation_id(hook_input)
    payload = {
        "client_surface": CLIENT_SURFACE,
        "tool_name": tool_name,
        "tool_input": {"file_path": file_path},
        "tool_output": content,
        "tool_response": {"content": content},
        "tool_call_id": vmcp_correlation_id,
        "tool_use_id": vmcp_correlation_id,
        "request_id": vmcp_correlation_id,
        "id": vmcp_correlation_id,
        "trace_id": vmcp_correlation_id,
        "session_id": session_id,
        "prompt_session_id": session_id,
        "agent_id": socket.gethostname(),
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "user_email": os.environ.get("TENETX_USER_EMAIL", ""),
        "hook_type": "response",
        "metadata": {
            "model": hook_input.get("model", ""),
            "turn_id": hook_input.get("turn_id", ""),
            "permission_mode": hook_input.get("permission_mode", ""),
        },
    }

    url = TENETX_URL + "/api/vmcp/" + TENETX_ORG + "/codex/check-response"

    try:
        timeout = _response_http_timeout()
        headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT, "X-TenetX-Response-Timeout-Ms": str(int(timeout * 1000))}
        if VMCP_TOKEN:
            headers["Authorization"] = "Bearer " + VMCP_TOKEN
        req = urllib.request.Request(
            url,
            data=_json_payload(payload, urlparse(url).path),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CONTEXT) as response:
            result = json.load(response)
        write_posture_marker(POSTURE_HEALTHY_VALUE, "tenetx_api_verified", "/codex/check-response")

        if result.get("modified"):
            masked = result.get("masked_content", "")
            if masked:
                debug_log("pre_tool_use_pii_masked file=" + file_path)
                return masked
    except Exception as e:
        debug_log("pre_tool_use_api_error=" + type(e).__name__ + " " + str(e)[:160])
        write_posture_marker(POSTURE_UNHEALTHY_VALUE, "tenetx_api_error:" + type(e).__name__, "/codex/check-response")

    return None


def _mask_file_via_api(filepath, hook_input, tool_input, tool_name="Bash"):
    """Read file, send to TenetX for masking, write masked temp file."""
    if not _should_scan(filepath):
        return None
    content = _read_file_content(filepath)
    if not content:
        return None
    masked_content = _send_to_tenetx(content, filepath, hook_input, tool_name=tool_name)
    if not masked_content:
        return None
    fd, tmppath = tempfile.mkstemp(prefix="tenetx-masked-", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(masked_content)
    return tmppath


def _handle_simple_read(parts, hook_input, tool_input):
    """Handle commands like: cmd [flags...] file"""
    if len(parts) < 2:
        return None
    cmd_name = parts[0]
    filename = parts[-1]
    filepath = _resolve_file_path(filename, hook_input, tool_input)
    tmppath = _mask_file_via_api(filepath, hook_input, tool_input, tool_name=cmd_name)
    if not tmppath:
        return None
    middle = parts[1:-1]
    new_cmd = " ".join([cmd_name] + middle + [tmppath])
    updated = dict(tool_input)
    updated["command"] = new_cmd
    return _pretooluse_allow_rewrite_payload(updated)


def _handle_diff(parts, hook_input, tool_input):
    """Handle: diff [flags...] file1 file2"""
    if len(parts) < 3:
        return None
    file1 = _resolve_file_path(parts[-2], hook_input, tool_input)
    file2 = _resolve_file_path(parts[-1], hook_input, tool_input)
    tmp1 = _mask_file_via_api(file1, hook_input, tool_input, tool_name="diff") or file1
    tmp2 = _mask_file_via_api(file2, hook_input, tool_input, tool_name="diff") or file2
    if tmp1 == file1 and tmp2 == file2:
        return None
    flags = parts[1:-2]
    new_cmd = " ".join(["diff"] + flags + [tmp1, tmp2])
    updated = dict(tool_input)
    updated["command"] = new_cmd
    return _pretooluse_allow_rewrite_payload(updated)


def _handle_python_inline(command, hook_input, tool_input):
    """Handle: python3 -c "...open('file')..." """
    match = re.search("open\\(['\"]([^'\"]+)['\"]\\)", command)
    if not match:
        return None
    filename = match.group(1)
    filepath = _resolve_file_path(filename, hook_input, tool_input)
    tmppath = _mask_file_via_api(filepath, hook_input, tool_input, tool_name="python_inline")
    if not tmppath:
        return None
    new_cmd = command.replace(filename, tmppath)
    updated = dict(tool_input)
    updated["command"] = new_cmd
    return _pretooluse_allow_rewrite_payload(updated)


import base64
import hashlib
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlencode, urlsplit

# Hook self-update metadata.
# - HOOK_VERSION identifies the currently running public hook artifact.
# - Update checks are client-initiated and rate-limited by a local TTL cache.
# - Bridge releases let older installs bootstrap signing before we require it.
HOOK_VERSION = "2.2.57"
AUTO_UPDATE_HOOK_TYPE = "codex"
DEFAULT_UPDATE_CHECK_TTL_SECONDS = int(os.environ.get("TENETX_UPDATE_CHECK_TTL", "3600"))
SIGNING_BOOTSTRAPPED = False
SUPPORTED_SIGNATURE_ALGORITHM = "rsa-pkcs1v15-sha256"
TRUSTED_SIGNING_KEY_ID = ""
TRUSTED_SIGNING_PUBLIC_KEY_PEM = """"""


def _runtime_debug(message):
    logger = globals().get("debug_log")
    if callable(logger):
        try:
            logger(message)
        except Exception:
            pass


def _runtime_ssl_context():
    context = globals().get("SSL_CONTEXT")
    if context is not None:
        return context
    factory = globals().get("_ssl_context")
    if callable(factory):
        try:
            return factory()
        except Exception:
            return None
    return None


def _runtime_user_agent():
    return str(globals().get("USER_AGENT") or "TenetX-VMCP-Hook/1.0")


def _runtime_tenetx_url():
    return str(globals().get("TENETX_URL") or globals().get("API_URL") or "").rstrip("/")


def _runtime_org_slug():
    return str(globals().get("TENETX_ORG") or globals().get("ORG_SLUG") or "")


def _runtime_token():
    token = globals().get("VMCP_TOKEN") or os.environ.get("TENETX_VMCP_TOKEN")
    if token:
        return str(token).strip()
    loader = globals().get("_load_token")
    if callable(loader):
        try:
            loaded = loader()
            if loaded:
                return str(loaded).strip()
        except Exception:
            pass
    token_file = os.environ.get("TENETX_VMCP_TOKEN_FILE")
    if token_file:
        try:
            with open(token_file, "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except Exception:
            pass
    return ""


def _runtime_timeout():
    value = globals().get("TIMEOUT")
    if value is None:
        value = globals().get("TIMEOUT_S")
    try:
        return float(value)
    except Exception:
        return 5.0


def _get_hook_layout():
    # Installer-managed layout:
    #   <hook_home>/current/tenetx-guard.py
    #   <hook_home>/versions/<version>/tenetx-guard.py
    #
    # Legacy single-file installs are still supported so existing users can
    # gain the updater after one refresh or reinstall.
    script_path = os.path.abspath(
        globals().get("__file__", os.path.join(os.getcwd(), "tenetx-guard.py"))
    )
    script_dir = os.path.dirname(script_path)
    parent_dir = os.path.dirname(script_dir)
    grandparent_dir = os.path.dirname(parent_dir)

    if os.path.basename(script_dir) == "current":
        hook_home = parent_dir
        current_script_path = script_path
        managed_layout = True
    elif os.path.basename(parent_dir) == "versions":
        hook_home = grandparent_dir
        current_script_path = os.path.join(hook_home, "current", os.path.basename(script_path))
        managed_layout = True
    else:
        hook_home = script_dir
        current_script_path = script_path
        managed_layout = False

    return {
        "script_name": os.path.basename(script_path),
        "script_path": script_path,
        "hook_home": hook_home,
        "current_script_path": current_script_path,
        "managed_layout": managed_layout,
        "state_path": os.path.join(hook_home, ".update-state.json"),
        "versions_dir": os.path.join(hook_home, "versions"),
    }


def _read_update_state(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            state = json.load(handle)
        return state if isinstance(state, dict) else {}
    except Exception:
        return {}


def _write_update_state(path, state):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tenetx-update-", suffix=".json", dir=parent or None)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


def _write_text_atomic(path, content):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tenetx-hook-", suffix=".py", dir=parent or None)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(tmp_path, 0o755)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


def _auth_headers():
    headers = {"User-Agent": _runtime_user_agent()}
    token = _runtime_token()
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers


def _http_json(url, payload=None):
    body = None
    headers = _auth_headers()
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=_runtime_timeout(), context=_runtime_ssl_context()) as response:
        return json.load(response)


def _http_text(url):
    request = urllib.request.Request(url, headers=_auth_headers())
    with urllib.request.urlopen(request, timeout=_runtime_timeout(), context=_runtime_ssl_context()) as response:
        return response.read().decode("utf-8")


def _build_signed_artifact_payload(hook_type, version, artifact_sha256):
    return (
        "scope=vmcp-hook-artifact\n"
        + "hook_type=" + hook_type + "\n"
        + "version=" + version + "\n"
        + "sha256=" + artifact_sha256 + "\n"
    ).encode("utf-8")


def _artifact_url_is_trusted(artifact_url):
    # Pin update artifacts to the control-plane origin. The manifest is
    # server-supplied; without this an attacker who can shape the manifest (a
    # compromised control plane, or a MITM when TLS verification is off) could
    # point artifact_url at their own host, which would both serve arbitrary
    # code and receive the bearer token attached by _auth_headers(). Real
    # artifacts are always served from {tenetx_url}/api/vmcp/.../script, i.e.
    # the exact origin (scheme + host + port) we already authenticate to.
    try:
        api = urlsplit(_runtime_tenetx_url())
        art = urlsplit(str(artifact_url or ""))
    except Exception:
        return False
    if not art.scheme or not art.hostname:
        return False
    return (
        art.scheme == api.scheme
        and (art.hostname or "").lower() == (api.hostname or "").lower()
        and art.port == api.port
    )


def _verify_release_signature(
    hook_type,
    version,
    artifact_sha256,
    signature_required,
    signature_b64,
    key_id,
    algorithm,
):
    # Mandatory-signature floor: once this client has a trusted signing key
    # baked in, never honor the manifest's signature_required=false. A
    # compromised or MITM'd control plane could otherwise flip that flag to
    # push unsigned (i.e. arbitrary) code onto every endpoint. Clients that
    # are not yet bootstrapped still take the bridge path so they can adopt
    # signing on their first refresh.
    if SIGNING_BOOTSTRAPPED and TRUSTED_SIGNING_PUBLIC_KEY_PEM.strip():
        signature_required = True
    if not signature_required:
        return
    if not SIGNING_BOOTSTRAPPED:
        raise ValueError("signing_not_bootstrapped")
    if not signature_b64:
        raise ValueError("signature_missing")
    if not key_id or key_id != TRUSTED_SIGNING_KEY_ID or not TRUSTED_SIGNING_PUBLIC_KEY_PEM.strip():
        raise ValueError("unknown_signing_key")
    if algorithm != SUPPORTED_SIGNATURE_ALGORITHM:
        raise ValueError("signature_algorithm_unsupported")
    openssl = shutil.which("openssl")
    if not openssl:
        raise ValueError("openssl_missing")

    payload = _build_signed_artifact_payload(hook_type, version, artifact_sha256)
    try:
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("signature_invalid") from exc

    tmp_paths = []
    try:
        for suffix in (".txt", ".pem", ".sig"):
            fd, path = tempfile.mkstemp(prefix=".tenetx-signature-", suffix=suffix)
            os.close(fd)
            tmp_paths.append(path)
        payload_path, public_key_path, signature_path = tmp_paths
        with open(payload_path, "wb") as handle:
            handle.write(payload)
        with open(public_key_path, "w", encoding="utf-8") as handle:
            handle.write(TRUSTED_SIGNING_PUBLIC_KEY_PEM)
        with open(signature_path, "wb") as handle:
            handle.write(signature)
        result = subprocess.run(
            [
                openssl,
                "dgst",
                "-sha256",
                "-verify",
                public_key_path,
                "-signature",
                signature_path,
                payload_path,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise ValueError("signature_invalid")
    finally:
        for path in tmp_paths:
            try:
                os.unlink(path)
            except Exception:
                pass


def _report_update(status, from_version, to_version, reason):
    token = _runtime_token()
    tenetx_url = _runtime_tenetx_url()
    org_slug = _runtime_org_slug()
    if not token or not tenetx_url or not org_slug:
        return
    report_url = tenetx_url + "/api/vmcp/" + org_slug + "/" + AUTO_UPDATE_HOOK_TYPE + "/update-report"
    try:
        _http_json(
            report_url,
            {
                "status": status,
                "from_version": from_version,
                "to_version": to_version,
                "reason": reason,
            },
        )
    except Exception as exc:
        _runtime_debug("update_report_error=" + type(exc).__name__ + " " + str(exc)[:160])


def _update_reason(exc):
    return str(exc) if isinstance(exc, ValueError) and str(exc) else type(exc).__name__


def _should_check_for_updates(hook_event):
    # Each platform has different lifecycle events.  We trigger update
    # checks on the earliest reliable event per platform.  The TTL cache
    # in _maybe_auto_update (default 1 hour) prevents redundant calls.
    #
    # Platform      Trigger event               Notes
    # ------------- --------------------------- --------------------------------
    # Claude Code   SessionStart                Fires on every new session
    # Codex         SessionStart                Same as Claude Code
    # Cursor        Any event (first wins)      sessionStart is buggy/missing;
    #                                           Cursor forum confirms gaps
    # Windsurf      pre_user_prompt / SessionStart
    #               Cascade first prompt; Devin Local session start.
    #               pre_cascade_request kept for leftover older guards.
    # OpenClaw      before_tool_call (any)      No sessionStart; gateway:startup
    #                                           is internal-only
    if AUTO_UPDATE_HOOK_TYPE == "windsurf":
        return hook_event in (
            "pre_user_prompt",
            "SessionStart",
            "pre_cascade_request",
        )
    if hook_event in ("SessionStart", "sessionStart"):
        return True
    if AUTO_UPDATE_HOOK_TYPE == "claude-code":
        return True
    if AUTO_UPDATE_HOOK_TYPE in ("cursor", "openclaw"):
        return True
    return False


def _maybe_auto_update(hook_event):
    token = _runtime_token()
    tenetx_url = _runtime_tenetx_url()
    org_slug = _runtime_org_slug()
    if not token or not tenetx_url or not org_slug:
        return
    if not _should_check_for_updates(hook_event):
        return

    layout = _get_hook_layout()
    state = _read_update_state(layout["state_path"])
    now = int(time.time())
    ttl = max(int(state.get("check_ttl_seconds") or DEFAULT_UPDATE_CHECK_TTL_SECONDS), 60)
    last_checked = int(state.get("last_checked_epoch") or 0)
    if last_checked and (now - last_checked) < ttl:
        return

    check_url = (
        tenetx_url
        + "/api/vmcp/"
        + org_slug
        + "/"
        + AUTO_UPDATE_HOOK_TYPE
        + "/version-check?"
        + urlencode(
            {
                "current_version": HOOK_VERSION,
                "signing_bootstrapped": "1" if SIGNING_BOOTSTRAPPED else "0",
                "signing_key_id": TRUSTED_SIGNING_KEY_ID,
            }
        )
    )

    _runtime_debug("update_check_started current=" + HOOK_VERSION)
    try:
        manifest = _http_json(check_url)
    except Exception as exc:
        _runtime_debug("update_check_error=" + type(exc).__name__ + " " + str(exc)[:160])
        return

    target_version = str(manifest.get("target_version") or "")
    state["last_checked_epoch"] = now
    state["check_ttl_seconds"] = int(manifest.get("check_ttl_seconds") or ttl)
    state["current_version"] = HOOK_VERSION
    if target_version:
        state["last_target_version"] = target_version

    # Always cache the latest runtime fail-mode so wrappers installed with
    # stale TENETX_FAIL_MODE env vars can self-correct when admins flip
    # the availability policy without forcing a reinstall.
    fail_mode = str(manifest.get("runtime_fail_mode") or "").strip().lower()
    if fail_mode in ("open", "closed", "tiered"):
        state["runtime_fail_mode"] = fail_mode
    if "local_failsafe" in manifest:
        state["local_failsafe"] = bool(manifest.get("local_failsafe"))

    if not manifest.get("update_available"):
        _write_update_state(layout["state_path"], state)
        if target_version and not manifest.get("selected_for_rollout", True):
            _runtime_debug("update_outside_rollout target=" + target_version)
        else:
            _runtime_debug("update_not_available")
        return

    artifact_url = str(manifest.get("artifact_url") or "")
    artifact_sha256 = str(manifest.get("artifact_sha256") or "")
    artifact_signature = str(manifest.get("artifact_signature") or "")
    signature_required = bool(manifest.get("signature_required"))
    signature_key_id = str(manifest.get("signature_key_id") or "")
    signature_algorithm = str(manifest.get("signature_algorithm") or "")
    if not artifact_url or not artifact_sha256 or not target_version:
        _write_update_state(layout["state_path"], state)
        _report_update("failure", HOOK_VERSION, target_version, "manifest_invalid")
        _runtime_debug("update_apply_failed reason=manifest_invalid")
        return

    if not _artifact_url_is_trusted(artifact_url):
        _write_update_state(layout["state_path"], state)
        _report_update("failure", HOOK_VERSION, target_version, "artifact_url_untrusted")
        _runtime_debug("update_apply_failed reason=artifact_url_untrusted")
        return

    _runtime_debug("update_download_started target=" + target_version)
    try:
        _verify_release_signature(
            AUTO_UPDATE_HOOK_TYPE,
            target_version,
            artifact_sha256,
            signature_required,
            artifact_signature,
            signature_key_id,
            signature_algorithm,
        )
        script_text = _http_text(artifact_url)
        actual_sha256 = hashlib.sha256(script_text.encode("utf-8")).hexdigest()
        if actual_sha256 != artifact_sha256:
            raise ValueError("checksum_mismatch")
        compile(script_text, artifact_url, "exec")

        version_path = os.path.join(layout["versions_dir"], target_version, layout["script_name"])
        _write_text_atomic(version_path, script_text)

        live_path = layout["current_script_path"] if layout["managed_layout"] else layout["script_path"]
        _write_text_atomic(live_path, script_text)

        state["current_version"] = target_version
        state["last_update_success_epoch"] = now
        state["last_update_failure_reason"] = ""
        _write_update_state(layout["state_path"], state)
        _runtime_debug("update_apply_succeeded target=" + target_version)
        _report_update("success", HOOK_VERSION, target_version, "updated")
    except Exception as exc:
        state["last_update_failure_epoch"] = now
        state["last_update_failure_reason"] = _update_reason(exc)
        _write_update_state(layout["state_path"], state)
        _runtime_debug("update_apply_failed reason=" + state["last_update_failure_reason"][:160])
        _report_update("failure", HOOK_VERSION, target_version, state["last_update_failure_reason"])

if __name__ == "__main__":
    main()
