#!/usr/bin/env bash
# Run directly in Terminal: nested Seatbelt startup is refused in managed sessions.
set -euo pipefail
umask 077
if [ "$(uname -s)" != Darwin ]; then
  echo 'The XIB broker tests require macOS.' >&2
  exit 1
fi
if [ "$#" -ne 4 ] || [ "$1" != --xcode-app ] || [ "$3" != --simulator-runtime ]; then
  echo 'Usage: bash scripts/test-macos-xib-broker.sh --xcode-app /Applications/Xcode.app --simulator-runtime /absolute/path/to/iOS.simruntime' >&2
  exit 2
fi
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
if ! command -v cargo >/dev/null; then
  if [ -x /private/tmp/runboundary-toolchain/bin/cargo ]; then
    export PATH="/private/tmp/runboundary-toolchain/bin:$PATH"
    export CARGO_HOME=/private/tmp/runboundary-cargo
  else
    echo 'Install a Rust stable toolchain first.' >&2
    exit 1
  fi
fi
export RUNBOUNDARY_TEST_XCODE_APP="$2"
export RUNBOUNDARY_TEST_SIMULATOR_RUNTIME="$4"
mkdir -p test-results
report="$repo_dir/test-results/macos-xib-broker-$(date -u +%Y%m%dT%H%M%SZ).log"
{
  printf 'RunBoundary constrained XIB broker tests\nReport: %s\n' "$report"
  sw_vers
  printf 'Explicit compiler-only approvals: Xcode=%s; runtime=%s; SimLaunchHost-arm64\n' "$2" "$4"
  echo 'Tests use synthetic inputs and canaries. No project scripts, credentials, device boot or session-creation requests.'
  echo 'Checks compiler-profile host-file/TCP denials, then a real isolated XIB compile and validated NIB publication.'
  cargo test --locked --lib interface_builder::tests::compiler_profile_denies_host_canaries_and_ip_networking -- --exact --ignored --nocapture --test-threads=1
  cargo test --locked --test interface_builder_test isolated_compiler_produces_a_nib_without_applying_source -- --exact --ignored --nocapture --test-threads=1
} 2>&1 | tee "$report"
