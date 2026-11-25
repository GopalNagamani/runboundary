#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin || $# -gt 1 ]]; then
  echo 'Usage on macOS: bash scripts/pack-npm-macos.sh [npm-package-name]' >&2
  exit 2
fi

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
target_dir="$repo_dir/target"
output_dir="$target_dir/npm"
staging_dir=$(mktemp -d "${TMPDIR:-/tmp}/runboundary-npm.XXXXXX")
trap 'rm -rf -- "$staging_dir"' EXIT
mkdir -p "$staging_dir/bin" "$output_dir"

cargo build --release --locked --bin runb --target-dir "$target_dir" \
  --target aarch64-apple-darwin

binary="$staging_dir/bin/runb"
install -m 0755 "$target_dir/aarch64-apple-darwin/release/runb" "$binary"
codesign --verify "$binary"

version=$("$binary" --version)
cp packaging/npm/package.json packaging/npm/README.md LICENSE "$staging_dir/"
npm --cache "$staging_dir/cache" --prefix "$staging_dir" \
  pkg set "version=${version#runb }" ${1:+"name=$1"}
npm --cache "$staging_dir/cache" pack --ignore-scripts \
  --pack-destination "$output_dir" "$staging_dir"
