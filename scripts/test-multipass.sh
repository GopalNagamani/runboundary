#!/usr/bin/env bash
# Run from the Mac's Terminal. Requires permission to access the Multipass daemon.
set -euo pipefail
umask 077
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
vm_name=agentvault-security-check
reuse=false
case "${1:-}" in
  '') ;;
  --reuse) reuse=true ;;
  *) echo 'Usage: bash scripts/test-multipass.sh [--reuse]' >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
  echo 'Too many arguments.' >&2
  exit 2
fi
command -v multipass >/dev/null || { echo 'Multipass is not installed.' >&2; exit 1; }
if [ "$reuse" = true ]; then
  # Only use --reuse for the dedicated VM this script created. Source is refreshed.
  multipass start "$vm_name"
else
  # Refuse an existing name rather than unexpectedly altering another VM.
  multipass launch 24.04 --name "$vm_name" --cpus 2 --memory 2G --disk 10G
fi
multipass exec "$vm_name" -- cloud-init status --wait

task_tmp=$(mktemp -d "${TMPDIR:-/tmp}/agentvault-vm.XXXXXX")
trap 'rm -rf -- "$task_tmp"' EXIT
# Transfer only the build/test source trees. Never mount a Mac directory.
COPYFILE_DISABLE=1 tar -czf "$task_tmp/source.tar.gz" -C "$repo_dir" \
  Cargo.toml Cargo.lock cmd internal tests examples
cat > "$task_tmp/check.sh" <<'GUEST'
#!/usr/bin/env bash
set -euo pipefail
umask 077
exec > >(tee "$HOME/agentvault-test.log") 2>&1
printf 'AgentVault Multipass validation: %s\n' "$(date -u)"
if [ "$(id -u)" -eq 0 ]; then
  echo 'Refusing to run security tests as root.'
  exit 1
fi
# These sudo commands install prerequisites only. Cargo and sandbox tests run
# as the ordinary ubuntu user. This runner does not modify AppArmor or sysctls.
sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  build-essential pkg-config curl ca-certificates bubblewrap python3 nodejs
if [ ! -x "$HOME/.cargo/bin/cargo" ]; then
  curl --proto '=https' --tlsv1.2 --fail --show-error --location \
    https://sh.rustup.rs -o /tmp/agentvault-rustup.sh
  sh /tmp/agentvault-rustup.sh -y --no-modify-path --profile minimal \
    --component rustfmt --component clippy
fi
export PATH="$HOME/.cargo/bin:$PATH"
rustup component add rustfmt clippy
uname -a
bwrap --version
rustc --version
cargo --version
python3 --version
node --version
printf '\nRead-only namespace diagnostics (missing keys are reported, not changed):\n'
for setting in user.max_user_namespaces kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns; do
  sysctl "$setting" || true
done
mkdir -p "$HOME/agentvault-source"
# A fresh per-run directory avoids stale build source on explicit --reuse.
source_dir=$(mktemp -d "$HOME/agentvault-source/run.XXXXXX")
tar -xzf /tmp/agentvault-source.tar.gz -C "$source_dir"
cd "$source_dir"
printf '\nCopied source directory: %s\n' "$source_dir"
failures=0
check() {
  printf '\nRUNNING:'
  printf ' %q' "$@"
  printf '\n'
  if "$@"; then
    printf 'CHECK PASSED\n'
  else
    status=$?
    printf 'CHECK FAILED (exit %s)\n' "$status"
    failures=$((failures + 1))
  fi
}
check cargo fmt --check
check cargo test --locked
check cargo clippy --locked --all-targets -- -D warnings
check cargo test --locked --no-fail-fast -- --ignored --nocapture --test-threads=1
printf '\nFailed check groups: %s\n' "$failures"
printf 'These checks do not certify live Codex/Claude login or interactive behavior.\n'
if [ "$failures" -ne 0 ]; then
  printf 'Investigate the failures. This test runner did not change AppArmor or sysctl policy.\n'
  exit 1
fi
GUEST
multipass transfer "$task_tmp/source.tar.gz" "$vm_name:/tmp/agentvault-source.tar.gz"
multipass transfer "$task_tmp/check.sh" "$vm_name:/tmp/agentvault-check.sh"
status=0
multipass exec "$vm_name" -- bash /tmp/agentvault-check.sh || status=$?
mkdir -p "$repo_dir/test-results"
report="$repo_dir/test-results/multipass-$(date -u +%Y%m%dT%H%M%SZ).log"
if multipass transfer "$vm_name:/home/ubuntu/agentvault-test.log" "$report"; then
  printf '\nTest report: %s\n' "$report"
else
  printf '\nCould not retrieve the report; inspect /home/ubuntu/agentvault-test.log inside the VM.\n' >&2
  status=1
fi
printf 'VM retained for investigation: %s\n' "$vm_name"
printf 'Rerun with updated source: bash scripts/test-multipass.sh --reuse\n'
printf 'Stop when finished: multipass stop %s\n' "$vm_name"
exit "$status"
