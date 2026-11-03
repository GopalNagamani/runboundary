#!/usr/bin/env bash
# Explicit authenticated smoke test. The actual Codex requests stay sandboxed.
set -euo pipefail
umask 077
if [ "$(uname -s)" != Darwin ]; then
  echo 'This diagnostic currently requires macOS.' >&2
  exit 1
fi
if [ "$#" -ne 2 ] || [ "$1" != --runtime-root ]; then
  echo 'Usage: bash scripts/diagnose-live-codex.sh --runtime-root /opt/homebrew' >&2
  exit 2
fi
if [ -z "${OPENAI_API_KEY:-}" ]; then
  echo 'Set OPENAI_API_KEY securely in this Terminal first. Never pass it as an argument.' >&2
  exit 1
fi
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
if ! command -v cargo >/dev/null && [ -x /private/tmp/agentvault-toolchain/bin/cargo ]; then
  export PATH="/private/tmp/agentvault-toolchain/bin:$PATH"
  export CARGO_HOME=/private/tmp/agentvault-cargo
fi
# Do not expose the API key to build scripts.
env -u OPENAI_API_KEY -u ANTHROPIC_API_KEY cargo build --locked
python3 scripts/diagnose-live-codex.py "$@"
