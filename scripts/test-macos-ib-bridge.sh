#!/usr/bin/env bash
# Tests typed IB/asset operations and the real Xcode build, then optionally your app.
set -euo pipefail
umask 077
if [ "$(uname -s)" != Darwin ]; then echo 'macOS is required.' >&2; exit 1; fi
from_fixture=false
allow_compiler_services=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --from-fixture) from_fixture=true; shift ;;
    --allow-compiler-simulator-services) allow_compiler_services=true; shift ;;
    *) break ;;
  esac
done
if { [ "$#" -ne 4 ] && [ "$#" -ne 10 ]; } || [ "${1:-}" != --xcode-app ] || [ "${3:-}" != --simulator-runtime ]; then
  echo 'Usage: bash scripts/test-macos-ib-bridge.sh [--from-fixture] [--allow-compiler-simulator-services] --xcode-app PATH --simulator-runtime PATH [--project PATH --workspace App.xcworkspace --scheme SCHEME]' >&2
  exit 2
fi
if [ "$#" -eq 10 ] && { [ "$5" != --project ] || [ "$7" != --workspace ] || [ "$9" != --scheme ]; }; then
  echo 'Optional arguments must be --project PATH --workspace NAME --scheme NAME.' >&2; exit 2
fi
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
if ! command -v cargo >/dev/null; then
  if [ -x /private/tmp/runboundary-toolchain/bin/cargo ]; then
    export PATH="/private/tmp/runboundary-toolchain/bin:$PATH"
    export CARGO_HOME=/private/tmp/runboundary-cargo
  else echo 'Install a Rust stable toolchain first.' >&2; exit 1; fi
fi
export RUNBOUNDARY_TEST_XCODE_APP="$2"
export RUNBOUNDARY_TEST_SIMULATOR_RUNTIME="$4"
export RUNBOUNDARY_TEST_COMPILER_SIMULATOR_SERVICES=0
compiler_flags=()
if [ "$allow_compiler_services" = true ]; then
  export RUNBOUNDARY_TEST_COMPILER_SIMULATOR_SERVICES=1
  compiler_flags=(--allow-compiler-simulator-services)
fi
mkdir -p test-results
report="$repo_dir/test-results/macos-ib-bridge-$(date -u +%Y%m%dT%H%M%SZ).log"
{
  printf 'RunBoundary Interface Builder and asset catalog bridge validation\nReport: %s\n' "$report"
  sw_vers
  printf 'Explicit Xcode=%s; compiler runtime=%s\n' "$2" "$4"
  printf 'Compiler Simulator services explicitly enabled: %s\n' "$allow_compiler_services"
  echo 'Only compiler jobs receive the approved runtime/helper connections. Build scripts use the ordinary sandbox.'
  if [ "$allow_compiler_services" = true ]; then
    echo 'Shared Apple services have host account authority and may create private build devices.'
    cargo test --locked --lib interface_builder::tests::compiler_profile_denies_host_canaries_and_ip_networking -- --exact --ignored --nocapture --test-threads=1
  fi
  if [ "$from_fixture" = false ]; then
    echo 'Running typed compiler jobs, followed by the synthetic unsigned app build through IBC_EXEC.'
    cargo test --locked --test ib_bridge_test typed_jobs_produce_xib_storyboard_link_and_auxiliary_outputs -- --exact --ignored --nocapture --test-threads=1
    cargo test --locked --test asset_bridge_test typed_asset_jobs_produce_car_icons_symbols_and_metadata -- --exact --ignored --nocapture --test-threads=1
  else
    echo 'Fixture-resume mode: typed compiler jobs are not selected in this run.'
  fi
  cargo test --locked --test ib_bridge_test xcode_build_uses_the_broker_for_xib_storyboard_and_link_steps -- --exact --ignored --nocapture --test-threads=1
  if [ "$#" -eq 10 ]; then
    echo 'Fixture passed. Starting the selected app build in a fresh filtered copy; no source changes are applied.'
    cargo run --locked --bin runb -- --project "$6" ios-build ${compiler_flags[@]+"${compiler_flags[@]}"} --workspace "$8" --scheme "${10}" --simulator-runtime "$4"
  fi
} 2>&1 | tee "$report"
