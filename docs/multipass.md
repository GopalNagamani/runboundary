# Test the real Linux sandbox using Multipass

Multipass runs an Ubuntu virtual machine on your Mac. AgentVault's Bubblewrap
sandbox runs inside that Linux VM. This guide tests the Linux backend. For the separate native macOS backend,
use the [macOS guide](macos.md).

From your Mac's Terminal:

```sh
cd /Users/hariprakashb/Desktop/agentvault
bash scripts/test-multipass.sh
```

The script creates `agentvault-security-check` using Ubuntu 24.04, 2 CPUs,
2 GiB RAM, and a 10 GiB virtual disk. It downloads Ubuntu, Linux packages, Rust,
and Cargo dependencies, so first setup can take several minutes. No Rust
installation is needed on the Mac to run this script.

It transfers an archive containing Cargo.toml, Cargo.lock, cmd, internal, tests,
and examples. It never mounts your Mac's folders or imports host credentials.
Tests use synthetic secret fixtures. Linux package installation uses sudo in
the VM; building and all sandbox tests run as the ordinary ubuntu user.

The script runs formatting, portable tests, Clippy, and the explicitly selected
real Bubblewrap tests. The report is copied back to `test-results/`. Read the
individual test results: normal tests listing OS tests as ignored is expected,
but the separate `--ignored` run must actually pass those tests. Installation or
namespace failures count as failures. No AppArmor or kernel policy is disabled.
Passing these checks does not validate live Codex/Claude API login, nested agent
sandbox compatibility, interactive terminal behavior, or signal forwarding.

The VM is retained for investigation. After fixing source, refresh and rerun:

```sh
bash scripts/test-multipass.sh --reuse
```

Use `--reuse` only for the dedicated VM created by this script. Each run gets a
new source directory; the log file inside the VM contains the latest run.
Historical reports copied to the Mac have timestamped filenames.

Stop the VM to release its running resources:

```sh
multipass stop agentvault-security-check
```

If `multipass socket access denied` occurs, VM work has not started from that
command. Run the script in your own Terminal. If it also fails there, resolve
Multipass daemon access using the Multipass application and its documented
authentication/troubleshooting steps. Do not change socket permissions broadly
or disable system security controls to bypass the error.

Script validation: the developer-run report `multipass-20261021T152829Z.log`
records formatting, 18 portable tests, strict Linux Clippy, and all 11 real OS
tests passing after the explicit AppArmor setup documented below. The assistant
inspected the supplied logs; its own Multipass socket remains inaccessible.
Live authenticated Codex/Claude sessions have not been tested.

References: [launch](https://canonical.com/multipass/docs/latest/reference/command-line-interface/launch/),
[transfer](https://canonical.com/multipass/docs/latest/reference/command-line-interface/transfer/),
[exec](https://canonical.com/multipass/docs/latest/reference/command-line-interface/exec/).

## Investigating UID-map permission failures

The second developer report, `multipass-20261021T151606Z.log`, confirms that
all four normal check groups except the real OS suite succeeded. All 11 real
OS tests stopped at startup with `bwrap: setting up uid map: Permission denied`.
It records `kernel.unprivileged_userns_clone=1`, a positive namespace limit,
and `kernel.apparmor_restrict_unprivileged_userns=1`. AppArmor is a likely
cause, but the kernel denial record is needed to establish the exact policy
and whether it interacts with pre-exec no_new_privs.

Collect a smaller report without rebuilding or changing policy:

```sh
bash scripts/diagnose-multipass.sh
```

This reuses the dedicated VM, prints installed Bubblewrap profile text and
loaded AppArmor status, and attempts two minimal Bubblewrap launches: direct
and with no_new_privs set before exec. Both retain user/PID isolation, capability
dropping, and nested-user-namespace restrictions. It then collects recent
kernel denial events using passwordless sudo in the VM. No packages, profiles,
sysctls, or sandbox flags are changed. Root access is used only to read profile
and audit information. The report is copied into `test-results/`.

A successful minimal diagnostic is not a passing AgentVault security suite.
Neither the direct launch nor the comparison disables the agent sandbox or
requests an unsandboxed agent launch. Do not disable the system-wide AppArmor
restriction or make Bubblewrap setuid to force the tests to pass.

Ubuntu documents application-specific user-namespace authorization and
purpose-built Bubblewrap profiles in its [AppArmor security documentation](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/)
and [user-namespace restriction explanation](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007).
Any required profile repair must be based on the denial evidence and the
installed distribution policy; the diagnostic script does not perform one.

## Confirmed missing-profile repair for the dedicated test VM

`multipass-diagnostic-20261021T152205Z.log` confirms that no Bubblewrap profile
is installed or loaded. Both direct and pre-exec-no_new_privs launches fail.
Kernel audit records show transition from `unconfined` into
`unprivileged_userns`, then denial of Bubblewrap's writes to `proc/.../uid_map`.
This establishes the current VM prerequisite failure; it is not evidence of
an AgentVault filesystem escape.

Run this explicit administrator setup from the Mac's Terminal, followed by
another real test run:

```sh
bash scripts/configure-multipass-apparmor.sh && bash scripts/test-multipass.sh --reuse
```

The setup operates only in `agentvault-security-check` and only on Ubuntu
24.04 with the global restriction enabled. It downloads the AppArmor project's
purpose-built helper/child policy at fixed commit
`1979af7710d0f38db6680bd7c19c80902f11f969`, checks SHA-256
`634d3d3427c483f123cb5ed53b71ea13040187e07d9f67ca74421d42a6170f0e`, and compiles
against the VM's AppArmor 4.0 ABI before loading it. The profile is saved as
`/etc/apparmor.d/agentvault-bwrap`. A different existing file or already-loaded
conflicting profile causes refusal. An identical previously installed copy
can be reloaded. Setup reports are copied into `test-results/`.

This is an explicit VM security-policy change: it grants the Bubblewrap helper
permissions needed for namespace setup, then stacks a child profile that
denies capabilities. It applies to every `/usr/bin/bwrap` invocation in this
VM, not exclusively AgentVault. Use the dedicated test VM; do not copy the
setup blindly to machines running other workloads. It does not grant host
root privileges, make Bubblewrap setuid, disable AppArmor, or change sysctls.
AgentVault still requests mandatory namespaces, nested-user-namespace
restrictions, capability dropping, descriptor closure, and no_new_privs.

Source: [AppArmor 4.0-compatible upstream profile](https://gitlab.com/apparmor/apparmor/-/blob/1979af7710d0f38db6680bd7c19c80902f11f969/profiles/apparmor/profiles/extras/bwrap-userns-restrict),
following the Bubblewrap-profile approach described in [Ubuntu's guidance](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007).
No third-party policy text is vendored in this repository. The downloaded policy
retains its upstream terms.

To undo only this setup inside the dedicated VM, unload its profiles and then
remove its file (the second operation runs only if unloading succeeds):

```sh
multipass exec agentvault-security-check -- sh -c 'sudo apparmor_parser --remove /etc/apparmor.d/agentvault-bwrap && sudo rm -- /etc/apparmor.d/agentvault-bwrap'
```

After removal, namespace setup may again be refused under Ubuntu's default
restriction. Stopping the VM alone does not remove its installed profile.

Validation: host and guest Bash syntax checks pass. The developer-supplied
setup report `multipass-apparmor-setup-20261021T152803Z.log` confirms the pinned
hash, successful profile loading in enforce mode, and the global restriction
still enabled. The subsequent `multipass-20261021T152829Z.log` records all 11
real sandbox tests passing. These results do not certify live agent sessions.
