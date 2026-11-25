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
  if [ -x /private/tmp/runboundary-toolchain/bin/cargo ]; then
    export PATH="/private/tmp/runboundary-toolchain/bin:$PATH"
    export CARGO_HOME=/private/tmp/runboundary-cargo
  else
    echo 'Install a Rust stable toolchain before running this script.' >&2
    exit 1
  fi
fi
mkdir -p test-results
run_stamp=$(date -u +%Y%m%dT%H%M%SZ)
report="$repo_dir/test-results/macos-$run_stamp.log"
checks="$repo_dir/test-results/macos-$run_stamp.checks.tsv"
printf 'status\texit_code\tcommand\n' > "$checks"
exec > >(tee "$report") 2>&1
printf 'RunBoundary native macOS validation: %s\nReport: %s\n' "$(date -u)" "$report"
sw_vers
uname -m
rustc --version
cargo --version
printf '\nSource fingerprints (compare these when reproducing this run):\n'
find internal cmd tests -type f -name '*.rs' -exec shasum -a 256 {} + | LC_ALL=C sort
shasum -a 256 Cargo.toml Cargo.lock scripts/test-macos.sh
if [ -n "$runtime_root" ]; then
  printf '\nExplicitly approved read-only runtime tree for these tests: %s\n' "$runtime_root"
  export RUNBOUNDARY_TEST_RUNTIME_ROOT="$runtime_root"
else
  unset RUNBOUNDARY_TEST_RUNTIME_ROOT || true
  echo 'No additional runtime tree approved. Python/Node tests require approved installations and may fail prerequisites.'
fi
failures=0
check() {
  printf '\nRUNNING:'
  printf ' %q' "$@"
  printf '\n'
  if "$@"; then
    echo 'CHECK PASSED'
    printf 'PASS\t0\t' >> "$checks"
  else
    check_code=$?
    printf 'CHECK FAILED (exit %s)\n' "$check_code"
    printf 'FAIL\t%s\t' "$check_code" >> "$checks"
    failures=$((failures + 1))
  fi
  printf '%q ' "$@" >> "$checks"
  printf '\n' >> "$checks"
}
check cargo fmt --check
check cargo test --locked
check cargo clippy --locked --all-targets -- -D warnings
# Select only native macOS tests, not the ignored Linux Bubblewrap suite.
check cargo test --locked --test macos_test -- --ignored --nocapture --test-threads=1
check cargo test --locked --test workflow_test -- --ignored --nocapture --test-threads=1
check cargo test --locked --test preview_test -- --ignored --nocapture --test-threads=1
check cargo test --locked --test toolchains_test -- --ignored --nocapture --test-threads=1
if [ -n "${RUNBOUNDARY_TEST_XCODE_APP:-}" ]; then
  printf '\nExplicitly approved Xcode test bundle: %s\n' "$RUNBOUNDARY_TEST_XCODE_APP"
  check cargo test --locked --test xcode_test -- --ignored --nocapture --test-threads=1
else
  echo '[NOT RUN] Optional real Xcode test: set RUNBOUNDARY_TEST_XCODE_APP to explicitly approve a bundle.'
fi
printf '\nFailed check groups: %s\nReport: %s\nCheck results: %s\n' "$failures" "$report" "$checks"
echo 'Scope: core native CLI checks. Xcode compiler, live provider, and independent security gates are separate.'
echo 'No agent API keys are imported. Tests use synthetic secrets. Live agent login is not certified by these tests.'
if [ "$failures" -ne 0 ]; then exit 1; fi
