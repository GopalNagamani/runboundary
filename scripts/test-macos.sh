#!/usr/bin/env bash
# Run directly in the Mac's Terminal; never from an already sandboxed session.
set -euo pipefail
umask 077
if [ "$(uname -s)" != Darwin ]; then
  echo 'This test runner requires macOS.' >&2
  exit 1
fi
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
runtime_root=''
if [ "$#" -ne 0 ]; then
  if [ "$#" -ne 2 ] || [ "$1" != --runtime-root ]; then
    echo 'Usage: bash scripts/test-macos.sh [--runtime-root /opt/homebrew]' >&2
    exit 2
  fi
  runtime_root=$2
fi
if ! command -v cargo >/dev/null; then
  if [ -x /private/tmp/agentvault-toolchain/bin/cargo ]; then
    export PATH="/private/tmp/agentvault-toolchain/bin:$PATH"
    export CARGO_HOME=/private/tmp/agentvault-cargo
  else
    echo 'Install a Rust stable toolchain before running this script.' >&2
    exit 1
  fi
fi
mkdir -p test-results
report="$repo_dir/test-results/macos-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee "$report") 2>&1
printf 'AgentVault native macOS validation: %s\nReport: %s\n' "$(date -u)" "$report"
sw_vers
uname -m
rustc --version
cargo --version
if [ -n "$runtime_root" ]; then
  printf '\nExplicitly approved read-only runtime tree for these tests: %s\n' "$runtime_root"
  export AGENTVAULT_TEST_RUNTIME_ROOT="$runtime_root"
else
  unset AGENTVAULT_TEST_RUNTIME_ROOT || true
  echo 'No additional runtime tree approved. Python/Node tests require approved installations and may fail prerequisites.'
fi
failures=0
check() {
  printf '\nRUNNING:'
  printf ' %q' "$@"
  printf '\n'
  if "$@"; then
    echo 'CHECK PASSED'
  else
    printf 'CHECK FAILED (exit %s)\n' "$?"
    failures=$((failures + 1))
  fi
}
check cargo fmt --check
check cargo test --locked
check cargo clippy --locked --all-targets -- -D warnings
# Select only native macOS tests, not the ignored Linux Bubblewrap suite.
check cargo test --locked --test macos_test -- --ignored --nocapture --test-threads=1
check cargo test --locked --test preview_test -- --ignored --nocapture --test-threads=1
check cargo test --locked --test toolchains_test -- --ignored --nocapture --test-threads=1
if [ -n "${AGENTVAULT_TEST_XCODE_APP:-}" ]; then
  printf '\nExplicitly approved Xcode test bundle: %s\n' "$AGENTVAULT_TEST_XCODE_APP"
  check cargo test --locked --test xcode_test -- --ignored --nocapture --test-threads=1
else
  echo '[NOT RUN] Optional real Xcode test: set AGENTVAULT_TEST_XCODE_APP to explicitly approve a bundle.'
fi
printf '\nFailed check groups: %s\nReport: %s\n' "$failures" "$report"
echo 'No agent API keys are imported. Tests use synthetic secrets. Live agent login is not certified by these tests.'
if [ "$failures" -ne 0 ]; then exit 1; fi
