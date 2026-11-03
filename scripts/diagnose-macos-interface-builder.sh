#!/usr/bin/env bash
set -euo pipefail
umask 077
if [ "$(uname -s)" != Darwin ]; then
  echo 'This diagnostic requires macOS.' >&2
  exit 1
fi
if { [ "$#" -ne 4 ] && [ "$#" -ne 5 ]; } || [ "${1:-}" != --xcode-app ] || [ "${3:-}" != --simulator-runtime ] || { [ "$#" -eq 5 ] && [ "$5" != --test-helper-connections ]; }; then
  echo 'Usage: bash scripts/diagnose-macos-interface-builder.sh --xcode-app /Applications/Xcode.app --simulator-runtime /absolute/path/to/iOS.simruntime [--test-helper-connections]' >&2
  exit 2
fi
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
export AGENTVAULT_TEST_XCODE_APP="$2"
export AGENTVAULT_TEST_SIMULATOR_RUNTIME="$4"
unset AGENTVAULT_TEST_ALLOW_SIMULATOR_SERVICES
if [ "$#" -eq 5 ]; then
  export AGENTVAULT_TEST_ALLOW_SIMULATOR_SERVICES=1
fi
mkdir -p test-results
report="$repo_dir/test-results/macos-ibtool-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee "$report") 2>&1
printf 'AgentVault fixed-XIB compilation diagnostic\nReport: %s\n' "$report"
sw_vers
printf 'Explicit read-only approvals: Xcode=%s; runtime=%s\n' "$2" "$4"
echo 'Approval trusts the administrator-installed SDK/runtime and macOS admin-group writers.'
echo 'Synthetic XIB only; no project build scripts, imported credentials, signing or production policy changes.'
if [ "$#" -eq 5 ]; then
  echo 'Explicit test-only helper connections enabled: shared Simulator helpers may use host account Simulator state. This does not certify their confinement.'
else
  echo 'Sandboxed candidates keep Simulator helper connections blocked.'
fi
echo 'Compares private Cocoa home/direct compiler/read-only runtime candidates. Candidate permissions are not saved.'
echo 'Production compilation must pass for this diagnostic to pass; a successful candidate alone is not a completed fix.'
service_status=0
if [ "$#" -eq 5 ]; then
  echo 'Running service tests: non-platform library rejection and an unknown-session spawn. Session creation is not requested because it crashes the shared service on the tested runtime. Uses fixed synthetic canaries, never real credentials or existing device sessions.'
  cargo test --locked --test macos_simulator_service_test -- --ignored --nocapture --test-threads=1 || service_status=$?
fi
compilation_status=0
cargo test --locked --test macos_ibtool_diagnostic diagnose_interface_builder -- --exact --ignored --nocapture --test-threads=1 || compilation_status=$?
printf 'Service canary test exit: %s; production compatibility diagnostic exit: %s\n' "$service_status" "$compilation_status"
if [ "$service_status" -ne 0 ] || [ "$compilation_status" -ne 0 ]; then
  exit 1
fi
