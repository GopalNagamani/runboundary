#!/usr/bin/env python3
"""Bounded real Codex requests through AgentVault; never logs raw credentials."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time
import unicodedata

MARKER = "AGENTVAULT_LIVE_CODEX_OK"
OUTPUT_LIMIT = 256 * 1024
PROVIDER_ID = "agentvault-diagnostic"


def provider_options(websockets):
    # Current Codex reserves built-in IDs, including "openai". Configure an
    # independent provider pointing to the same official API, never that ID.
    prefix = f"model_providers.{PROVIDER_ID}."
    settings = [
        ("model_provider", PROVIDER_ID),
        (prefix + "name", "AgentVault OpenAI diagnostic"),
        (prefix + "base_url", "https://api.openai.com/v1"),
        (prefix + "env_key", "OPENAI_API_KEY"),
        (prefix + "wire_api", "responses"),
        (prefix + "supports_websockets", websockets),
        (prefix + "request_max_retries", 0),
        (prefix + "stream_max_retries", 0),
        (prefix + "stream_idle_timeout_ms", 10000),
        ("web_search", "disabled"),
    ]
    options = ["--no-daemon", "-a", "never"]
    for name, value in settings:
        options.extend(["-c", f"{name}={json.dumps(value)}"])
    return options


def redact(text, key):
    if key:
        text = text.replace(key, "[REDACTED]")
        text = text.replace(json.dumps(key)[1:-1], "[REDACTED]")
    # Provider errors may echo a partially masked API key rather than its value.
    text = re.sub(r"\bsk-[A-Za-z0-9_*.-]+", "[REDACTED]", text)
    return "".join(
        c if c in "\n\t" or unicodedata.category(c) not in ("Cc", "Cf")
        else f"\\u{ord(c):04x}" for c in text
    )


def capture(command, env, timeout=60, limit=OUTPUT_LIMIT):
    """Drain concurrently with a deadline; withhold any oversized output whole."""
    child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             start_new_session=True)
    output = bytearray()
    overflow = False
    timed_out = False
    deadline = time.monotonic() + timeout
    ended_at = None
    eof = False
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    try:
        while not eof:
            if child.poll() is not None:
                ended_at = ended_at or time.monotonic()
                if time.monotonic() - ended_at > 2:
                    break
            if time.monotonic() >= deadline:
                timed_out = True
                if child.poll() is None:
                    # AgentVault forwards this signal to its sandbox process.
                    child.send_signal(signal.SIGTERM)
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
                deadline = float("inf")
                ended_at = time.monotonic()
            for _key, _event in selector.select(timeout=0.1):
                chunk = os.read(child.stdout.fileno(), 8192)
                if not chunk:
                    eof = True
                    break
                if not overflow and len(output) + len(chunk) <= limit:
                    output.extend(chunk)
                else:
                    overflow = True
                    output.clear()
        child.wait(timeout=5)
    finally:
        selector.close()
        child.stdout.close()
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
    if overflow or not eof:
        text = "Output withheld: oversized or incomplete diagnostic capture."
    else:
        text = output.decode("utf-8", errors="replace")
    return child.returncode, text, timed_out


def verified(text):
    # Do not count an echoed prompt, config text or a failed turn as a reply.
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict) or event.get("type") != "item.completed":
            continue
        item = event.get("item", {})
        if isinstance(item, dict) and item.get("type") == "agent_message":
            if item.get("text", "").strip() == MARKER:
                return True
    return False


def quota_blocked(text):
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        message = None
        if event.get("type") == "error":
            message = event.get("message")
        elif event.get("type") == "turn.failed":
            error = event.get("error", {})
            if isinstance(error, dict):
                message = error.get("message")
        if isinstance(message, str):
            lowered = message.lower()
            if "quota exceeded" in lowered or "insufficient_quota" in lowered:
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-root", required=True)
    args = parser.parse_args()
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key:
        parser.error("OPENAI_API_KEY must be set in your Terminal; never pass it as an argument")
    repo = Path(__file__).resolve().parent.parent
    binary = repo / "target/debug/agentvault"
    directory = repo / "test-results"
    directory.mkdir(exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report = directory / f"codex-live-{stamp}.log"
    descriptor = os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as log:
        def emit(text):
            safe = redact(text, key)
            print(safe, flush=True)
            log.write(safe + "\n")
            log.flush()

        emit(f"AgentVault bounded live Codex verification\nReport: {report}")
        emit("Uses your explicitly approved API key for up to two short model requests. API charges may apply.")
        emit("Fresh synthetic project; no host login cache, raw credential logs, or policy relaxation.")
        # AgentVault filters this further; unrelated host credentials/proxies are
        # deliberately absent even from the diagnostic parent command's env.
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TERM": "dumb",
               "LANG": "C", "OPENAI_API_KEY": key}
        with tempfile.TemporaryDirectory(prefix="agentvault-live-codex-", dir="/private/tmp") as tmp:
            project = Path(tmp)
            (project / ".env").write_text("FAKE_SECRET=synthetic-only\n")
            base = [str(binary), "--project", str(project)]
            code, text, expired = capture(base + ["init", "--runtime-root", args.runtime_root], env)
            emit(f"Initialization: exit={code}, timeout={expired}\n{text}")
            if code != 0 or expired:
                return 1
            for mode, websockets in [
                ("websocket-requested", True),
                ("http-sse-requested", False),
            ]:
                emit(f"RUNNING {mode}; at most 60 seconds, provider retries disabled")
                options = provider_options(websockets)
                command = base + ["run", "--auth-env", "OPENAI_API_KEY", "--", "codex"] + options + [
                    "exec", "--skip-git-repo-check", "--ephemeral", "--json",
                    "--sandbox", "danger-full-access",
                    f"Do not use tools or edit files. Reply with exactly {MARKER}.",
                ]
                code, text, expired = capture(command, env)
                emit(f"{mode}: exit={code}, timeout={expired}\n{text}")
                if code == 0 and not expired and verified(text):
                    emit(f"LIVE MODEL REPLY VERIFIED: {mode}. This does not verify interactive editing or synchronization.")
                    return 0
                if quota_blocked(text):
                    emit("Provider quota/billing blocked inference. Skipping further transport attempts; check the API key's project credits and usage limits before retrying. Live model reply NOT verified.")
                    return 1
            emit("Live model reply NOT verified. Inspect the redacted errors; no sandbox permissions were changed.")
            return 1


if __name__ == "__main__":
    raise SystemExit(main())
