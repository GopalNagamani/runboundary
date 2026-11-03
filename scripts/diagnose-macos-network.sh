#!/usr/bin/env bash
# Explicit, unauthenticated public HTTPS probes; no production policy changes.
set -euo pipefail
umask 077
if [ "$(uname -s)" != Darwin ]; then
  echo 'This diagnostic requires macOS.' >&2
  exit 1
fi
if [ "$#" -ne 2 ] || [ "$1" != --runtime-root ]; then
  echo 'Usage: bash scripts/diagnose-macos-network.sh --runtime-root /opt/homebrew' >&2
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
report="$repo_dir/test-results/macos-network-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee "$report") 2>&1
printf 'AgentVault macOS DNS/HTTPS diagnostic\nReport: %s\n' "$report"
sw_vers
printf 'Explicit read-only runtime approval: %s\n' "$2"
echo 'No API keys or model calls. Public requests go to https://api.openai.com/v1/models without authentication; HTTP 401 confirms connectivity.'
echo 'Production policy is unchanged. This checks direct networking; proxy values and credentials are not inherited.'
cargo test --locked --test macos_network_diagnostic diagnose_macos_provider_network -- --exact --ignored --nocapture --test-threads=1
