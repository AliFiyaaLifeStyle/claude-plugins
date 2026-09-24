#!/usr/bin/env python3
"""Credential bootstrap for the committed TenetX Codex Cloud hook."""
import base64, json, os, pathlib, sys, time

def _breadcrumb(reason):
    try:
        path = pathlib.Path.home() / ".tenetx" / "capture_failures.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "hook": "codex-cloud", "reason": reason}) + "\n")
    except Exception:
        pass

def _apply_explicit_env():
    """Local/ngrok path: TENETX_URL + ORG + VMCP_TOKEN, no packed secret.

    A packed TENETX_CODEX_TOKEN minted against sanketlocal.local.tenetx.ai
    embeds a host Codex Cloud cannot reach. Operators can set the three
    values separately and point TENETX_URL at an ngrok (or staging) origin.
    """
    url = str(os.environ.get("TENETX_URL") or "").strip().rstrip("/")
    org = str(os.environ.get("TENETX_ORG") or "").strip()
    token = str(os.environ.get("TENETX_VMCP_TOKEN") or "").strip()
    if not url or not org or not token:
        return False
    if not url.lower().startswith("https://") and not url.lower().startswith("http://"):
        return False
    os.environ.update({
        "TENETX_URL": url,
        "TENETX_ORG": org,
        "TENETX_VMCP_TOKEN": token,
        "TENETX_CLIENT_SURFACE": "codex-cloud",
        "TENETX_CODEX_PERMISSION_ASK_MODE": "defer",
    })
    return True

def _apply_secret():
    raw = str(os.environ.get("TENETX_CODEX_TOKEN") or "").strip()
    if not raw.startswith("txcc1."):
        return False
    try:
        blob = raw.split(".", 1)[1]
        payload = json.loads(base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4)))
        url, org, token = str(payload["u"]).rstrip("/"), str(payload["o"]).strip(), str(payload["t"]).strip()
        if not url or not org or not token: raise ValueError("empty field")
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        _breadcrumb("codex_cloud_token_decode_failed")
        return False
    os.environ.update({"TENETX_URL": url, "TENETX_ORG": org, "TENETX_VMCP_TOKEN": token, "TENETX_CLIENT_SURFACE": "codex-cloud", "TENETX_CODEX_PERMISSION_ASK_MODE": "defer"})
    return True

def main():
    # Packed secret wins when both are set, matching Claude Code cloud.
    if not _apply_secret() and not _apply_explicit_env():
        _breadcrumb("codex_cloud_token_missing_or_invalid")
        return 0
    guard = pathlib.Path(__file__).with_name("tenetx-guard.py")
    if not guard.is_file():
        _breadcrumb("codex_cloud_guard_missing")
        return 0
    os.execv(sys.executable, [sys.executable, str(guard), *sys.argv[1:]])
    return 0

if __name__ == "__main__": raise SystemExit(main())
