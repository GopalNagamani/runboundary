#!/usr/bin/env bash
# Explicit administrator setup for the dedicated Ubuntu 24.04 test VM only.
# The profile is upstream's confined helper/child policy, not an unconfined stub.
set -euo pipefail
umask 077
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
vm_name=runboundary-security-check
if [ "$#" -ne 0 ]; then
  echo 'Usage: bash scripts/configure-multipass-apparmor.sh' >&2
  exit 2
fi
command -v multipass >/dev/null
multipass start "$vm_name"
task_tmp=$(mktemp -d "${TMPDIR:-/tmp}/runboundary-apparmor.XXXXXX")
trap 'rm -rf -- "$task_tmp"' EXIT
cat > "$task_tmp/configure.sh" <<'GUEST'
#!/usr/bin/env bash
set -euo pipefail
umask 077
exec > >(tee "$HOME/runboundary-apparmor-setup.log") 2>&1
printf 'RunBoundary dedicated VM AppArmor setup: %s\n' "$(date -u)"
if [ "$(id -u)" -eq 0 ]; then
  echo 'Start this script as the ordinary ubuntu user.' >&2
  exit 1
fi
. /etc/os-release
if [ "$ID" != ubuntu ] || [ "$VERSION_ID" != 24.04 ]; then
  echo 'This setup is restricted to the diagnosed Ubuntu 24.04 test VM.' >&2
  exit 1
fi
if [ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" != 1 ]; then
  echo 'Expected the system-wide user-namespace restriction to remain enabled; refusing setup.' >&2
  exit 1
fi
command -v bwrap >/dev/null
sudo -n test -r /etc/apparmor.d/abi/4.0
sudo -n test -r /sys/kernel/security/apparmor/profiles
printf '\nInstalling a reviewed upstream profile for /usr/bin/bwrap in this VM.\n'
printf 'The profile permits helper setup, then stacks a child profile denying capabilities.\n'
printf 'AppArmor and all RunBoundary sandbox controls remain enabled.\n'
profile_url='https://gitlab.com/apparmor/apparmor/-/raw/1979af7710d0f38db6680bd7c19c80902f11f969/profiles/apparmor/profiles/extras/bwrap-userns-restrict'
expected_sha='634d3d3427c483f123cb5ed53b71ea13040187e07d9f67ca74421d42a6170f0e'
destination=/etc/apparmor.d/runboundary-bwrap
scratch=$(mktemp -d /tmp/runboundary-apparmor.XXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
candidate="$scratch/bwrap-userns-restrict"
curl --proto '=https' --tlsv1.2 --fail --show-error --location "$profile_url" -o "$candidate"
printf '%s  %s\n' "$expected_sha" "$candidate" | sha256sum -c -
printf '\nProfile source: %s\nSHA-256: %s\n' "$profile_url" "$expected_sha"
# Compile against this VM's ABI before making any policy changes.
sudo -n apparmor_parser --skip-kernel-load "$candidate"
if sudo -n test -e "$destination" || sudo -n test -L "$destination"; then
  if sudo -n test -L "$destination" || ! sudo -n test -f "$destination"; then
    echo 'Refusing an unsafe existing destination.' >&2
    exit 1
  fi
  installed_sha=$(sudo -n sha256sum "$destination")
  installed_sha=${installed_sha%% *}
  if [ "$installed_sha" != "$expected_sha" ]; then
    echo 'Existing RunBoundary profile differs; refusing to overwrite administrator policy.' >&2
    exit 1
  fi
  echo 'The identical profile is already installed; reloading it.'
  sudo -n apparmor_parser --replace "$destination"
else
  profiles=$(sudo -n cat /sys/kernel/security/apparmor/profiles)
  if printf '%s\n' "$profiles" | grep -Eq '^(bwrap|unpriv_bwrap) '; then
    echo 'Another bwrap or unpriv_bwrap policy is loaded; administrator review is required.' >&2
    exit 1
  fi
  sudo -n install -o root -g root -m 0644 "$candidate" "$destination"
  if ! sudo -n apparmor_parser --add "$destination"; then
    echo 'Profile loading failed; attempting to remove only the newly added policy.' >&2
    if sudo -n apparmor_parser --remove "$destination"; then
      sudo -n rm -- "$destination"
    else
      echo 'Policy cleanup could not be confirmed. Inspect the retained profile and setup log before retrying.' >&2
    fi
    exit 1
  fi
fi
profiles=$(sudo -n cat /sys/kernel/security/apparmor/profiles)
for name in bwrap unpriv_bwrap; do
  if ! printf '%s\n' "$profiles" | grep -Fxq "$name (enforce)"; then
    printf 'Required enforcing profile is missing: %s\n' "$name" >&2
    exit 1
  fi
done
if [ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" != 1 ]; then
  echo 'Unexpected global policy change detected; stop and investigate.' >&2
  exit 1
fi
printf '\nBoth profiles are loaded in enforce mode; global user-namespace restriction is still 1.\n'
printf 'Profile installation is not proof of sandbox startup. Run the real test suite next.\n'
GUEST
multipass transfer "$task_tmp/configure.sh" "$vm_name:/tmp/runboundary-configure-apparmor.sh"
status=0
multipass exec "$vm_name" -- bash /tmp/runboundary-configure-apparmor.sh || status=$?
mkdir -p "$repo_dir/test-results"
report="$repo_dir/test-results/multipass-apparmor-setup-$(date -u +%Y%m%dT%H%M%SZ).log"
if multipass transfer "$vm_name:/home/ubuntu/runboundary-apparmor-setup.log" "$report"; then
  printf '\nSetup report: %s\n' "$report"
else
  echo 'Could not retrieve setup report.' >&2
  status=1
fi
if [ "$status" -eq 0 ]; then
  echo 'Next: bash scripts/test-multipass.sh --reuse'
fi
exit "$status"
