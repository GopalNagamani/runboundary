#!/usr/bin/env bash
# Run from Terminal. No project scripts, existing Simulator sessions or credentials.
set -euo pipefail
umask 077
if [ "$(uname -s)" != Darwin ]; then
  echo 'This test requires macOS.' >&2
  exit 1
fi
if [ "$#" -ne 4 ] || [ "$1" != --xcode-app ] || [ "$3" != --simulator-runtime ]; then
  echo 'Usage: bash scripts/test-macos-simulator-spawn.sh --xcode-app /Applications/Xcode.app --simulator-runtime /absolute/path/to/iOS.simruntime' >&2
  exit 2
fi
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
if ! command -v cargo >/dev/null; then
  if [ -x /private/tmp/agentvault-toolchain/bin/cargo ]; then
    export PATH="/private/tmp/agentvault-toolchain/bin:$PATH"
    export CARGO_HOME=/private/tmp/agentvault-cargo
  else
    echo 'Install a Rust stable toolchain before running this script.' >&2
    exit 1
  fi
fi
export AGENTVAULT_TEST_XCODE_APP="$2"
export AGENTVAULT_TEST_SIMULATOR_RUNTIME="$4"
export AGENTVAULT_TEST_ALLOW_SIMULATOR_SERVICES=1
mkdir -p test-results
report="$repo_dir/test-results/macos-simulator-spawn-$(date -u +%Y%m%dT%H%M%SZ).log"
{
printf 'AgentVault Simulator unknown-session spawn test\nReport: %s\n' "$report"
sw_vers
printf 'Explicit test-only approvals: Xcode=%s; read-only runtime=%s; SimLaunchHost-arm64 connection\n' "$2" "$4"
echo 'Synthetic files and a fresh session identifier only. No existing Simulator/device sessions, project builds, signing or imported credentials.'
echo 'Attempts only an unknown-session child launch; unexpected acceptance fails. Session creation is not requested: it crashes the shared service on the tested runtime.'
echo 'This test does not certify existing-session ownership, all service operations or full iOS builds.'
cargo test --locked --test macos_simulator_service_test simulator_service_rejects_unknown_session_spawn -- --exact --ignored --nocapture --test-threads=1
} 2>&1 | tee "$report"
