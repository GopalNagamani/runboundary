#!/usr/bin/env bash
# Synthetic-only policy comparison; never launches a coding agent.
set -euo pipefail
umask 077
if [ "$(uname -s)" != Darwin ]; then
  echo 'This diagnostic requires macOS.' >&2
  exit 1
fi
if [ "$#" -ne 2 ] || [ "$1" != --runtime-root ]; then
  echo 'Usage: bash scripts/diagnose-macos-process.sh --runtime-root /opt/homebrew' >&2
  exit 2
fi
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
if ! command -v cargo >/dev/null && [ -x /private/tmp/agentvault-toolchain/bin/cargo ]; then
  export PATH="/private/tmp/agentvault-toolchain/bin:$PATH"
  export CARGO_HOME=/private/tmp/agentvault-cargo
fi
export AGENTVAULT_TEST_RUNTIME_ROOT="$2"
mkdir -p test-results
report="$repo_dir/test-results/macos-process-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee "$report") 2>&1
printf 'AgentVault synthetic process-isolation diagnostic\nReport: %s\n' "$report"
sw_vers
printf 'Explicit read-only runtime approval: %s\n' "$2"
echo 'No coding agents are launched. Only synthetic markers are read; process contents are never printed.'
cargo test --locked --test macos_test diagnose_process_data_isolation -- --exact --ignored --nocapture --test-threads=1
