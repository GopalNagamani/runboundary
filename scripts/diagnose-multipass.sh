#!/usr/bin/env bash
# Collect evidence from the dedicated VM. No packages or security policies change.
set -euo pipefail
umask 077
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
vm_name=agentvault-security-check
if [ "$#" -ne 0 ]; then
  echo 'Usage: bash scripts/diagnose-multipass.sh' >&2
  exit 2
fi
command -v multipass >/dev/null
multipass start "$vm_name"
task_tmp=$(mktemp -d "${TMPDIR:-/tmp}/agentvault-diagnostic.XXXXXX")
trap 'rm -rf -- "$task_tmp"' EXIT
cat > "$task_tmp/diagnose.sh" <<'GUEST'
#!/usr/bin/env bash
set -euo pipefail
umask 077
exec > >(tee "$HOME/agentvault-diagnostic.log") 2>&1
printf 'AgentVault namespace diagnostics: %s\n' "$(date -u)"
if [ "$(id -u)" -eq 0 ]; then
  echo 'Run diagnostics as the ordinary ubuntu user, not root.'
  exit 1
fi
uname -a
id
bwrap --version
dpkg-query -W bubblewrap apparmor 2>&1 || true
printf '\nCurrent AppArmor label:\n'
cat /proc/self/attr/current || true
printf '\nKernel namespace settings (read-only):\n'
for setting in user.max_user_namespaces kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns kernel.apparmor_restrict_unprivileged_unconfined; do
  sysctl "$setting" || true
done
printf '\nInstalled Bubblewrap AppArmor profile text:\n'
for profile in /etc/apparmor.d/*bwrap*; do
  if [ -f "$profile" ]; then
    printf '\nPROFILE FILE: %s\n' "$profile"
    sudo -n cat "$profile" || true
  fi
done
printf '\nLoaded AppArmor profiles:\n'
sudo -n aa-status 2>&1 || true
printf '\nMinimal Bubblewrap checks: no project, credentials, or home mounts.\n'
# Each command gets a fresh namespace and read-only administrator runtimes.
# These are diagnostic checks, not substitutes for the AgentVault security suite.
args=(--unshare-user --unshare-pid --unshare-ipc --unshare-uts
      --disable-userns --assert-userns-disabled --die-with-parent --new-session
      --cap-drop ALL --ro-bind /usr /usr --symlink usr/bin /bin
      --symlink usr/lib /lib --symlink usr/lib64 /lib64
      --proc /proc --dev /dev --tmpfs /tmp --remount-ro / -- /usr/bin/id)
printf '\nPROBE: direct Bubblewrap\n'
if env -i PATH=/usr/bin:/bin HOME=/tmp /usr/bin/bwrap "${args[@]}"; then
  echo 'Direct probe exit: 0'
else
  printf 'Direct probe exit: %s\n' "$?"
fi
printf '\nPROBE: Bubblewrap with no_new_privs set BEFORE exec (as AgentVault does)\n'
if command -v setpriv >/dev/null; then
  if env -i PATH=/usr/bin:/bin HOME=/tmp setpriv --no-new-privs /usr/bin/bwrap "${args[@]}"; then
    echo 'Pre-exec no_new_privs probe exit: 0'
  else
    printf 'Pre-exec no_new_privs probe exit: %s\n' "$?"
  fi
else
  echo 'setpriv unavailable; comparison was not run.'
fi
printf '\nRecent kernel AppArmor / user namespace / Bubblewrap events:\n'
sudo -n journalctl -k --since '15 minutes ago' --no-pager \
  --grep='apparmor|userns|bwrap' --case-sensitive=no -n 100 2>&1 || true
printf '\nDiagnostic collection complete. Probe exit codes above are the results.\n'
printf 'No AppArmor profiles, sysctls, package installations, or sandbox settings were changed.\n'
GUEST
multipass transfer "$task_tmp/diagnose.sh" "$vm_name:/tmp/agentvault-diagnose.sh"
status=0
multipass exec "$vm_name" -- bash /tmp/agentvault-diagnose.sh || status=$?
mkdir -p "$repo_dir/test-results"
report="$repo_dir/test-results/multipass-diagnostic-$(date -u +%Y%m%dT%H%M%SZ).log"
if multipass transfer "$vm_name:/home/ubuntu/agentvault-diagnostic.log" "$report"; then
  printf '\nDiagnostic report: %s\n' "$report"
else
  echo 'Could not retrieve report; inspect /home/ubuntu/agentvault-diagnostic.log in the VM.' >&2
  status=1
fi
exit "$status"
