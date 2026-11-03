#!/usr/bin/env bash
# Empty synthetic workspace only; no user project build scripts or policy edits.
set -euo pipefail
umask 077
if [ "$(uname -s)" != Darwin ]; then
  echo 'This diagnostic requires macOS.' >&2
  exit 1
fi
if [ "$#" -ne 2 ] || [ "$1" != --xcode-app ]; then
  echo 'Usage: bash scripts/diagnose-macos-xcode.sh --xcode-app /Applications/Xcode.app' >&2
  exit 2
fi
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
export AGENTVAULT_TEST_XCODE_APP="$2"
mkdir -p test-results
report="$repo_dir/test-results/macos-xcode-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee "$report") 2>&1
printf 'AgentVault synthetic Xcode workspace diagnostic\nReport: %s\n' "$report"
sw_vers
printf 'Explicit read-only SDK approval: %s\n' "$2"
echo 'Empty synthetic workspace, no app builds, credentials, signing, license acceptance or policy changes.'
echo 'Each command is bounded to 30 seconds. Denial lookup selects synthetic sandbox PIDs only.'
echo 'Diagnostic-only comparisons add one named CoreServices lookup, a literal account-record read, or both; production policy is unchanged.'
cargo test --locked --test macos_xcode_diagnostic diagnose_workspace_discovery -- --exact --ignored --nocapture --test-threads=1
