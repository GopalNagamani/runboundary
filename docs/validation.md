# Validation status and release gates

**Latest native macOS result: all checks pass in the supplied
`macos-20261021T171714Z.log`: 22 regular tests, 15 real native tests,
formatting and strict Clippy.** Tested on macOS 26.5.1 (25F80), arm64,
Rust 1.99.1, with explicit read-only `/opt/homebrew` runtime approval.
The temporary native CLI launch block has been removed. The report verifies
the tested filesystem/process-data behaviors; live authenticated Codex/Claude
sessions and production readiness remain unverified. Earlier failure records
below are retained as investigation history and are superseded by this result.

Initial development host: macOS (Darwin), 2026-10-21. No Rust toolchain initially installed. A temporary Rust 1.99.1 toolchain was installed under /private/tmp for development. Dependencies were fetched from crates.io and builds ran offline against Cargo.lock. These environment-specific paths are not required by the project.

**The supplied Linux report `multipass-20261021T152829Z.log` records all checks passing: 18 portable tests, 11 real OS sandbox tests, formatting, and strict Clippy. Live authenticated Codex/Claude sessions are still unverified; the MVP acceptance criteria remain incomplete.**

Tested platform: Ubuntu 24.04 aarch64 in Multipass, Linux 6.8.0-147-generic, Bubblewrap 0.9.0, Rust 1.99.1. The developer executed the VM commands and supplied the logs; the assistant inspected those logs. The assistant's own Multipass socket remains inaccessible. A later experimental native macOS backend is now implemented; its current validation status is recorded at the end of this document.

The successful run followed explicit installation of the pinned upstream AppArmor helper/child policy in the dedicated VM. Setup report `multipass-apparmor-setup-20261021T152803Z.log` records both profiles in enforce mode and the global user-namespace restriction still enabled. See [Multipass setup](multipass.md) for the policy scope and reproduction instructions. This result applies to the tested configuration and covered behaviors, not all Linux distributions or attack paths.

## Phase results

| Phase | Implemented | Verification and remaining risks |
| --- | --- | --- |
| 1: Foundation | Rust/clap modules, strict YAML, mandatory baseline and narrow exceptions, metadata-only init, real doctor builder | Portable policy/init tests pass. Doctor probes the explicitly selected platform backend; native macOS positive validation remains blocked in the managed session. Cobra is replaced by clap because Cobra is Go-only. |
| 2: Isolation | Descriptor-relative copy, no-follow/link checks, explicit 0700 parent, Bubblewrap namespace/mount builder, filtered environment, actual startup probe | Portable link/special-file/traversal tests and the real Linux isolation suite pass in the tested VM. A test caught and fixed reliance on permissive temporary-directory defaults. |
| 3: Agents | Trusted system executable resolution, Codex disposable-home API-key login, Claude API-key environment, inherited terminal I/O, supervisor signals and exit mapping | Explicit-auth tests pass; live agent versions, login, terminal modes, nested agent sandbox compatibility, signals, and network access remain unvalidated. No home-install/OAuth support or silent relaxation. |
| 4: Changes | Summaries, retained review records, escaped previews, explicit apply, conflict checks, no-replace installation, originals and intent journal, rollback, JSONL audit | Portable tests cover add/modify/delete, protected-output rejection, host-edit conflicts, review approval, and induced mid-commit rollback. Crash/power-loss recovery is manual and not atomic. |
| 5: Hardening | Link/special-file/adversarial tests, file/total-size and traversal bounds, environment allowlist, capabilities/namespace probes, inherited-FD closure tests, docs, CI | Local and native Linux lint checks and all 11 implemented OS tests pass. Broader adversarial coverage, interactive subprocess lifetime tests, dependency/security review, and independent architecture review remain release gates. Landlock/seccomp are not implemented. |

## Check commands

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
rustup target add aarch64-unknown-linux-gnu
cargo check --locked --target aarch64-unknown-linux-gnu --all-targets
```

Cross-target cargo check only type-checks Linux code; it does not run Linux binaries or establish sandbox behavior. The normal test suite explicitly lists ignored OS tests. The suite contains 18 portable tests and 11 OS tests ignored by the default command. All 29 passed in the supplied Linux report across the two test invocations; the OS suite must still be selected separately when reproducing.

On an unprivileged supported Linux host:

```sh
uname -a
bwrap --version
python3 --version
node --version
cargo test --locked --no-fail-fast -- --ignored --nocapture --test-threads=1
```

Real tests create synthetic project secrets and invoke Bubblewrap with the same production command builder. They exercise direct reads, Python, Node, subprocesses, template reads, permitted source edits, original-project access, credential-directory paths, Docker sockets, sandbox-created symlinks, failed startup, exit codes, and inherited descriptor closure. Portable tests separately cover preparation links, special files, traversal and synchronization. Synthetic SSH/AWS files and a live Unix socket are created in a separate host-only temporary directory, so their absence inside the sandbox is tested against present-on-host canaries. Additional mount-inspection and namespace tests are advisable before release.

Explicitly selected real tests fail on unsupported hosts rather than silently returning success. Missing Python/Node is a prerequisite failure in those selected tests; omit the specific ignored test only with an explicitly recorded reason. CI's sandbox job intentionally fails if runner policy prevents namespaces; it does not disable host security controls.

## Agent version matrix

| Agent | Intended installation/authentication | Certified version |
| --- | --- | --- |
| Codex | Administrator-managed Linux runtime; explicitly approved OPENAI_API_KEY piped to sandbox-local `login --with-api-key`; file credentials in disposable home | None; live Linux validation required |
| Claude Code | Administrator-managed Linux runtime; explicitly approved ANTHROPIC_API_KEY; first-run key approval may be interactive | None; live Linux validation required |

For each release candidate record exact versions, Linux distribution/kernel, Bubblewrap version, agent command line without credentials, auth method, terminal behavior, signal behavior, successful source edit/review/application, and the full real-test report. Do not use real secrets in adversarial fixtures.

Authentication implementation references: [Codex API-key login and credential storage](https://developers.openai.com/codex/auth), [Claude Code authentication](https://code.claude.com/docs/en/authentication). These describe the intended integration; they are not evidence that this implementation has passed a live session.

## Historical investigation (superseded by the passing run above)

### First supplied Multipass report and follow-up

The developer ran `scripts/test-multipass.sh` and supplied
`test-results/multipass-20261021T150826Z.log`. It records Ubuntu 24.04 on
aarch64, Linux 6.8.0-147-generic, Bubblewrap 0.9.0, and Rust 1.99.1.
The original 16 portable tests passed natively on Linux. Strict Linux Clippy
failed on redundant mode-type casts, and all five filesystem security tests
failed at their common sandbox startup probe. Cargo then stopped before
executing the remaining OS test binaries. These are startup failures, not
completed filesystem-access tests.

Follow-up changes compare native libc mode types, expose bounded/redacted
Bubblewrap stderr and labeled isolation-check failures, omit provider keys
from the local probe, and run all OS test binaries using `--no-fail-fast`.
The Multipass script also records namespace sysctl values without changing
them. The current 18 portable tests, native macOS Clippy, Linux-target Clippy,
and Bash syntax checks pass locally. The specific Linux startup cause is
not yet established: rerun `bash scripts/test-multipass.sh --reuse` from the
developer's Terminal. The assistant session still receives Multipass socket
access denied, including when attempting to execute commands in this VM.
No sandbox control or host security policy was relaxed.

The second supplied report, `multipass-20261021T151606Z.log`, records successful
formatting, 18 portable tests, and native Linux Clippy. All 11 real OS tests
failed during shared startup with `bwrap: setting up uid map: Permission denied`.
Kernel namespace settings allow user namespaces generally; Ubuntu's AppArmor
restriction is enabled. AppArmor is a likely cause pending kernel-denial and
installed-profile evidence. `scripts/diagnose-multipass.sh` collects that
read-only evidence and compares direct versus pre-exec-no_new_privs launches.
Its host and guest Bash syntax checks pass; execution still requires the
developer's Terminal because the assistant cannot access the Multipass socket.

`multipass-diagnostic-20261021T152205Z.log` establishes the prerequisite cause:
no Bubblewrap profile is present, and AppArmor's `unprivileged_userns` profile
denies writes to `proc/.../uid_map` during both direct and pre-exec-NNP probes.
An explicit dedicated-VM setup script now prepares the upstream AppArmor
helper/child policy pinned to an AppArmor 4.0-compatible commit and SHA-256.
It checks syntax before installation, refuses conflicting policies, checks
that the profiles are enforced and the global restriction stays enabled, and
records a separate setup report. This is a scoped policy change for the
Bubblewrap executable throughout the VM, not an AgentVault runtime fallback.
Host/guest Bash syntax and the downloaded hash are checked; actual loading and
post-setup Linux tests still await a developer-run report. See multipass.md.

## Passing Linux evidence

The developer supplied `test-results/multipass-20261021T152829Z.log`. It records:

- `cargo fmt --check`: passed.
- `cargo test --locked`: 18 portable tests passed, 11 OS tests ignored as expected.
- `cargo clippy --locked --all-targets -- -D warnings`: passed.
- `cargo test --locked --no-fail-fast -- --ignored --nocapture --test-threads=1`: 11 OS tests passed, none failed or ignored.
- Overall failed check groups: 0.

The real suite covers protected .env/.env.production reads, Python/Node reads,
permitted template/source access, descendants, host-project and synthetic
credential/socket exclusion, unsafe links, exit codes, descriptor inheritance,
regular-file standard-stream refusal, and startup failure. Its successful
preflight also checks effective capabilities and no_new_privs. This proves the
assertions exercised by these tests in this VM, not a complete security proof.

Outstanding validation includes live agent versions/API login, terminal modes,
signal forwarding and orphan cleanup, nested agent sandbox compatibility,
provider connectivity, and an end-to-end agent edit/review/apply session.
Independent security review and broader adversarial testing remain necessary.

## Native macOS implementation (later extension)

A separate `seatbelt` backend, host-specific initialization, explicit Homebrew
runtime approval, private on-disk home/temp directories, a default-deny SBPL
policy, descriptor closure, process-session handling, and 14 real macOS tests
are now implemented. Linux still uses Bubblewrap and mismatched configurations
are refused. See [the native macOS guide](macos.md) and
`bash scripts/test-macos.sh --runtime-root /opt/homebrew`.

The subsequent full report `macos-20261021T171444Z.log` records all 22 regular
tests and lint passing, but all 15 native tests failing. The replacement of
the startup self-information rule caused SIGTRAP during bootstrap, commonly
with `/private/var/select/sh` permission errors. The diagnostic still proves
that retaining the original self rule and appending the family denial works
for direct process-data reads. The generator now reproduces that exact
composition: the startup rule is restored and `(deny process-info*)` is
appended after all generated grants. No additional filesystem reads were
granted in response to the bootstrap error. Regular tests and strict native
Clippy pass. The complete production-policy native suite must be rerun;
CLI launches remain gated until it passes.

`macos-20261021T171714Z.log` validates the final policy composition: all
15 native tests pass. Sandbox startup, permitted edits, Python/Node secret
denials, original-project and host credential exclusion, Unix socket denial,
inherited descriptor closure, protected synchronization rejection, exit codes,
failed-profile refusal and outbound TCP all pass. Both process-data APIs
return EPERM with no synthetic argument/environment markers visible, directly
and through a spawned child. The unsandboxed control and reconstructed
historical profile retrieve both markers, confirming that the denied data is
actually present. The CLI block is removed without changing the verified
policy or mandatory runtime probe. All 22 regular tests and formatting/Clippy
also pass in the supplied report. After removing the CLI block, regular tests,
native test compilation and strict native/Linux-target Clippy are rerun locally;
no new native enforcement result is inferred from local managed-session checks.

First live Codex attempt: doctor passes with an explicitly approved credential,
but launch fails before login completes with `Error opening
/private/var/select/sh: Operation not permitted`; no file changes are produced.
The host path is a root-owned shell selector symlink to `/bin/bash`. The
profile now grants only the selector's literal read path and metadata access
to its ancestors, after verifying that its target is a trusted system runtime
outside the project. It does not grant the whole `/private/var/select` tree
or relax the final process-info denial. A sixteenth ignored native test checks
a Node-spawned shell pipeline. Its unsandboxed synthetic positive control
passes locally; all 22 regular tests, native test compilation and strict
native/Linux-target Clippy pass. The modified policy still needs a full native
suite rerun and live login retry from Terminal; credential validity has not
been established by this failed session.

`macos-20261021T174908Z.log` confirms all 16 native tests, 22 regular tests,
formatting and strict Clippy passing after the shell-selector allowance.
The subsequent live Codex retry still fails login, but the former wrapper
suppressed the underlying stderr. Login now executes as a separate sandboxed
phase in the same disposable home, passing the key over stdin. Its stderr is
drained concurrently into at most 64 KiB, redacted before display truncation,
and terminal-escaped; oversized output is withheld entirely. Diagnostics are
not written to audit logs or the workspace. Successful login then starts the
interactive agent with the same file-credential setting. The sandbox policy
is unchanged. Tests exercise a real subprocess emitting a synthetic token and
failing with status 23, and oversized output containing a token across the
capture limit. All 24 regular tests, native test compilation and strict
native/Linux-target Clippy pass. A live retry is needed to expose the actual
Codex failure; no authentication success is claimed yet.

The next live attempt exposes the actual blocker: Codex cannot check
`/etc/codex/requirements.toml` (EPERM), before validating the key. On the
development host `/private/etc/codex` is absent. The generator now permits
literal probes of the three documented system policy filenames through both
alias and canonical paths, with ancestor metadata only. Existing requirements
must be a trusted regular single-link file; existing defaults are refused to
avoid importing possible credentials. The directory must not be a symlink.
A seventeenth native test distinguishes absent optional policies from
permission failures. All 24 regular tests, formatting and strict native and
Linux-target Clippy pass. The changed native policy requires a full suite
rerun followed by a live retry. References: [managed requirements](https://learn.chatgpt.com/docs/enterprise/managed-configuration)
and [configuration layers](https://learn.chatgpt.com/docs/config-file/config-basic).

The developer next reports Codex opening, but model connectivity repeatedly
reconnecting. Opening the UI/login completion is not successful authenticated
inference. The existing network test covers localhost TCP only. A separate
explicit internet diagnostic now compares DNS, Node HTTPS and system-curl
HTTPS against the same unauthenticated public OpenAI endpoint, outside the
sandbox with a clean environment and inside production/candidate profiles.
It imports no API keys or proxy values and never relaxes production policy.
Candidate rules are based on the installed Apple system-network and trustd
profile entries; no candidate is claimed necessary or verified yet. All
24 regular tests, formatting, native test compilation, strict native/Linux
Clippy and script syntax pass. Actual diagnosis requires a Terminal report.

`macos-network-20261021T181138Z.log` confirms clean-host DNS, Node HTTPS and
curl HTTPS succeed (HTTP 401), with no host proxy/CA environment overrides.
Production DNS fails with ENOTFOUND; curl fails opening the system
`/private/etc/ssl/openssl.cnf`. None of the initial service-only candidates
fixes DNS. The system-file generator now preserves each permitted resolver
alias as well as its canonical target and grants read access to the specific
OpenSSL configuration file. This does not grant a system-directory subtree,
new Mach service or host socket access, and the final process-info denial is
unchanged. Resolver alias omission is a candidate cause, not yet verified.
An eighteenth native test checks read/open of these named runtime files and
resolver readlink operations without printing their contents. The internet
diagnostic adds file-open/readlink results and best-effort macOS denial logs
filtered to its own unauthenticated probe PIDs, plus a network-query candidate.
No missing/unsupported denial log is treated as proof of safety. All 24
regular tests, formatting and strict native/Linux-target Clippy pass. Native
DNS/HTTPS and the updated security suite still require a developer rerun.

The complete `macos-network-20261021T181810Z.log` identifies the minimal
working control: after the resolver/OpenSSL file corrections, adding only
`(allow network-outbound (literal "/private/var/run/mDNSResponder"))` makes
Node DNS succeed and both Node/curl HTTPS return HTTP 401. Production without
that exception still fails resolution. No additional Mach brokers, sysctl
families or host-directory reads are needed by these probes. The production
profile now includes that exact DNS socket exception. Unrelated Unix sockets
remain denied; the existing real socket test now positively verifies the
OS DNS socket can connect and a live synthetic host Docker socket cannot.
The diagnostic tests the exact production profile and reconstructs the old
no-DNS-socket policy for comparison. Other log denials in the successful
candidate were tolerated by the runtime and are not automatically allowed.
Full native security/provider-connectivity reruns and a live Codex retry are
still required for the changed production profile; no inference success is
claimed from unauthenticated HTTP 401 responses.

`macos-20261021T182255Z.log` records all 24 regular tests, 18 real native
security tests, formatting and Clippy passing. The companion
`macos-network-20261021T182337Z.log` confirms production DNS succeeds and
Node/curl both reach the public endpoint with HTTP 401. The developer still
reports Codex reconnecting, so successful authenticated inference remains
unverified. A bounded live diagnostic now performs actual Codex exec calls
inside the unchanged production sandbox, first default transport then an
explicit HTTP/SSE request if needed, with provider retries disabled and a
fresh synthetic project. It passes only the approved API key, captures errors
in bounded memory, redacts credentials before printing/writing, and requires
a real completed JSON model reply plus successful exit. Four offline tests
verify redaction, real subprocess exit handling, timeout/output limits and
rejection of echoed prompts as false success; all pass. Script syntax also
passes. The assistant has not executed authenticated inference; this requires
the developer's Terminal and may incur API charges. Transport/retry settings
are documented in the [official configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).

`codex-live-20261021T183608Z.log` shows both attempts stopped before inference:
the initial diagnostic tried to override the reserved built-in provider ID
`openai`, which installed Codex 0.163.0 rejects. The diagnostic now uses a
custom `agentvault-diagnostic` provider with the official API URL, an env-key
reference, explicit WebSocket/HTTP requests and bounded retries. Both generated
configurations were actually loaded successfully by the installed CLI using
`features list`, a disposable CODEX_HOME and no API credentials or network
model calls. All five offline harness tests pass, including a regression
against reserved-ID overrides. Shell syntax passes. The original reconnect
cause remains unresolved until an actual model attempt produces evidence;
this fixes the diagnostic configuration, not a proven transport failure.

`codex-live-20261021T184213Z.log` reaches actual model requests and reports
`invalid peer certificate: UnknownIssuer` from Codex's Rust WebSocket client;
HTTP also reconnects until the diagnostic deadline. Both attempts remain
unverified, even though signal-driven shutdown returns exit 0, because the
harness correctly requires no timeout and an actual completed agent reply.
The macOS environment now explicitly sets `CODEX_CA_CERTIFICATE` and
`SSL_CERT_FILE` to the existing public OS CA PEM bundle. The installed Codex
binary contains both variable names and official documentation confirms their
use for HTTPS/login/WebSockets. Root ownership, ancestor permissions, regular
file type, single-link identity and nonempty size are checked before launch.
No new filesystem or broker grants are added and TLS verification is not
disabled. A nineteenth native test loads root CAs and asserts certificate and
hostname verification remain enabled. A host positive control successfully
parses that bundle. All 24 regular tests, five offline harness tests,
formatting and strict native/Linux-target Clippy pass. Native security and
authenticated live inference must be rerun; this is an implemented candidate
fix for the observed trust error, not an authenticated success claim.

`macos-20261021T184901Z.log` records all 19 native security tests and the
regular checks passing. `codex-live-20261021T184907Z.log` shows the TLS fix
working: both requested transport modes reach the provider and receive a
structured `Quota exceeded. Check your plan and billing details.` error,
without UnknownIssuer or reconnect loops. This verifies provider-error
round trips, not successful inference or the precise negotiated transport.
The remaining blocker is the API account/project quota or billing state,
which AgentVault cannot resolve. The diagnostic now stops on a structured
quota error rather than trying another transport. All six offline harness
tests pass, including quota classification without treating model reply text
as an actual quota error. A completed model reply and interactive edit/review/
apply remain unverified until quota is available. No sandbox change is needed
in response to this provider quota error.

The macOS development host can compile and run portable tests. A selected real
macOS test was actually attempted using the production builder and stopped at
`sandbox-exec: sandbox_apply: Operation not permitted` (exit 71). This managed
assistant session cannot apply a second sandbox, so no native filesystem test
has passed here. An earlier test fixture's attempt to bind a Unix socket was
also refused by the managed environment; that fixture is now created only by
the socket-specific test. These are explicitly reported environment failures,
not skipped or successful OS checks.

Portable coverage includes a positive-control inherited-descriptor test
(the descriptor is present before hardening and absent afterward), parameter
injection defenses, refusal of broad runtime roots/backend fallback, private
credential-directory cleanup and symlink-safe cleanup. Strict Clippy is run
both natively and for aarch64-unknown-linux-gnu. The historical passing Linux
report above predates this extension; Linux runtime regression tests should
also be rerun before release. Native tests and live agent login/terminal/TLS
compatibility remain release gates. A macOS CI job now explicitly selects the
native suite instead of treating its default ignored status as a pass.

Current native portable results: 22 tests passed, 25 OS tests ignored by the
default command (11 Linux and 14 macOS). Formatting, native Clippy, and strict
Linux-target Clippy pass. The macOS shell test runner passes Bash syntax
checks. No successful native filesystem-enforcement or live-agent report is
available yet. Native tests must be explicitly selected from Terminal.

A native CLI smoke check also completed: `init --runtime-root /opt/homebrew`
generated a Seatbelt policy, Homebrew Node resolution succeeded, and `run`
refused execution at the managed session's sandbox_apply boundary. The
synthetic host source stayed unchanged. Standard Homebrew admin-group writable
ancestors are trusted only with explicit runtime approval; world/non-admin
group writable paths are still rejected. This smoke check is a fail-closed
startup check, not successful native confinement evidence.

The developer's native report `macos-20261021T162921Z.log` records formatting,
22 portable tests and strict Clippy passing, but all 14 selected native tests
failing at shared preflight with SIGABRT. The matching Terminal-owned
`sh-2026-10-21-215924.ips` crash report shows dyld's `libignition` bootstrap
aborting before shell execution. Apple's installed
`/System/Library/Sandbox/Profiles/dyld-support.sb` documents that libignition
must open `/` as its openat root. The profile now permits reading that literal
directory (including its entry names), without allowing descendant reads.
This is a targeted compatibility fix awaiting a fresh native test report;
the crash report alone does not prove that it is the only missing permission.

The follow-up `macos-20261021T163419Z.log` confirms the loader fix: sandbox
preflight succeeds and 13 of 14 native tests pass. Passing cases include direct,
Python and Node secret reads being denied, host credentials and writes being
denied, descendant/symlink confinement, inherited descriptor closure, Unix
socket denial, permitted edits, exit codes, invalid-profile refusal, protected
sync rejection and outbound TCP. Formatting, 22 portable tests and Clippy pass.
The remaining host-process-environment test fails earlier during Python's
`ctypes` import because `os.uname()` is denied; it has not yet exercised its
target sysctl assertion. The profile now additionally permits the exact public
`kern.version` sysctl used for uname, matching Apple's installed container
profile. Host-process argument/environment sysctls remain denied. This change
requires a fresh native report; all 14 tests have not yet passed together.

`macos-20261021T163647Z.log` again records 22 portable tests, formatting,
Clippy and 13 native tests passing. The remaining test reaches its sysctl
assertion, but its size-only query succeeds. That query does not transfer
arguments or environment bytes, so this result does not establish credential
exposure or effective protection. The test now attempts a real buffered read,
and its unsandboxed positive control must retrieve a synthetic environment
token. The sandboxed read must fail with EPERM/EACCES. No filesystem or process
permissions were widened for this test correction. Formatting and strict
native Clippy pass; the corrected OS test awaits execution from Terminal.

`macos-20261021T163827Z.log` records the same 13 native passes; the remaining
test fails because the unsandboxed control returns data without the synthetic
environment token. A local direct sysctl reproduction confirms this behavior.
The fixture now retains a synthetic argument in a waiting shell's argv and
requires the positive control to retrieve that marker. This actual buffered
positive-control read was reproduced successfully locally. The sandboxed
buffered read still must fail with EPERM/EACCES; no policy permissions changed.
This exercises the process argument/environment query endpoint, without
claiming the unsandboxed host exposes environment bytes on this OS version.
Formatting and strict Clippy pass. The native suite must be rerun.

`macos-20261021T164140Z.log` again has 13 native passes. The corrected
positive control succeeds, but the sandboxed read does not produce the
expected EPERM/EACCES result. Its original assertion did not report return
code, errno or marker visibility, so this report cannot distinguish a readable
buffer from a different error. The test now reports those nonsecret values
and only whether the synthetic marker is visible. Native process-data
confinement remains unresolved; native agent use is not certified.

`macos-20261021T164355Z.log` establishes actual disclosure: the sandboxed
buffered query returns 0, errno 0, 77 bytes, with the synthetic argument marker
visible. Thirteen other native tests pass. This is a real isolation failure,
not an assertion-format or prerequisite problem. A mandatory native preflight
release gate now refuses agent launch even after successful filesystem checks,
until process-data isolation is fixed and verified. No test was weakened to
accept the disclosure. Formatting and strict native Clippy pass after the
gate change. The native suite now stops at that gate; no repeat developer run
is requested while the underlying issue remains unresolved. Linux is unchanged.

Follow-up investigation adds a focused synthetic policy comparison:
`bash scripts/diagnose-macos-process.sh --runtime-root /opt/homebrew`.
The test compares the original policy and five explicit denial variants,
attempting actual buffered KERN_PROCARGS and KERN_PROCARGS2 reads. Unlike the
earlier Apple-signed shell fixture, the Homebrew Python fixture exposes both
synthetic argument and environment markers to the unsandboxed control; this
was verified locally for both APIs. Candidate processes must complete the
payload and return EPERM/EACCES to count as blocked; startup failures never
pass. This diagnostic only bypasses preflight in test code; the production
release gate remains in place. The managed session rejects all six candidate
launches with sandbox_apply exit 71, so no candidate is yet verified. The
developer's Terminal is needed to obtain the comparison report. All 22 regular
tests, formatting, strict native Clippy and shell syntax checks pass; the new
diagnostic is the fifteenth ignored native OS test.

`macos-process-20261021T171112Z.log` identifies the working control on macOS
26.5.1 arm64: explicit `(deny process-info*)` returns EPERM for both
KERN_PROCARGS and KERN_PROCARGS2; the synthetic argument and environment
markers are both absent. The original policy and named/prefix/global
sysctl-read denials still return both markers. Consequently, the production
profile replaces `(allow process-info* (target self))` with the explicit
family denial. No syscall-only rule is claimed to fix this endpoint.

The permanent regression now requires positive controls for both argument and
environment retrieval from a synthetic Homebrew Python process, then requires
EPERM/EACCES from both APIs directly and through a shell-spawned child. The
comparison diagnostic additionally reconstructs the historical vulnerable
profile to demonstrate exposure and compare restrictions. CLI run/doctor
release gating is separate from the backend probe so all 15 native tests can
validate the candidate while agent launches remain disabled. No environment
or configuration switch bypasses that CLI gate. All 22 portable tests pass;
native test compilation, formatting and strict native/Linux-target Clippy
pass. Run the full native suite from Terminal before removing the CLI gate:
`bash scripts/test-macos.sh --runtime-root /opt/homebrew`.

## Explicit ChatGPT file authentication (2026-10-22)

Added opt-in `--codex-auth-file` for run/doctor, ChatGPT-only field filtering,
private session-home copies, API-key mode conflicts, no-follow bounded imports,
and tests rejecting unsafe source files. Linux now binds the private disposable
home across the login/agent processes; no host home is mounted. API-key login
also benefits from this session-local cache persistence.

Local validation: 27 regular Rust tests passed (16 library, 8 integration, 3
filesystem preparation); native and aarch64 Linux all-target strict Clippy passed.
Added real macOS and Linux synthetic authentication-copy tests that exercise
credential visibility, original-file exclusion, persistence and cleanup. The
macOS test was attempted here and refused at preflight with `sandbox_apply:
Operation not permitted` in the managed execution environment. It is **not a
passing native security test**; run `bash scripts/test-macos.sh --runtime-root
/opt/homebrew` from Terminal. Linux real tests must be rerun in a supported Linux
environment. No real ChatGPT credential was read by the implementation tests;
no live model request was made. ChatGPT inference and refresh remain unverified.

## Retained workspace preview (2026-10-22)

Added `preview SESSION_ID [--port PORT] -- COMMAND`, fresh credential-free
private home/temp, mandatory OS preflight, terminal/signal supervision, exit-code
preservation, post-command rescan, and no automatic apply. The original baseline
is retained, so subsequent review includes preview-generated changes. A shared
per-session flock prevents concurrent preview/review/apply; private session path
validation rejects substituted workspace symlinks.

Validation: 31 regular Rust tests passed, including four new preview CLI,
locking, substituted-path and listener-policy tests. Native macOS and aarch64
Linux all-target strict Clippy passed. The actual Seatbelt parser initially
rejected numeric listener addresses; corrected to `localhost:PORT`, which parses
and then fails at the managed environment's `sandbox_apply` restriction.
Real preview-edit/isolation test was attempted and refused at mandatory preflight
with `sandbox_apply: Operation not permitted`. The HTTP round-trip test was
attempted and could not create its local control listener (`Operation not
permitted`) in this managed session. These are not native security passes.

Three real tests in `tests/preview_test.rs` cover excluded secrets/host project,
credential filtering, repeated preview, failed-command edits and later approval,
protected output rejection, and an actual host-to-sandbox HTTP response with
macOS unapproved listener checks. They are included in `scripts/test-macos.sh`;
Linux's existing all-ignored integration invocation also selects them. Run from
Terminal/on supported Linux before relying on the feature. No model requests or
real credentials are used. Existing total-size and blanket symlink restrictions
still apply to build/dependency output.

### Terminal report macos-20261022T051139Z.log

The supplied Terminal report passed formatting, 31 regular tests, strict Clippy,
all 20 real macOS security tests, and two of three real preview tests (isolated
edits/repeated preview/explicit apply, and protected output rejection). The browser
preview test failed before listening: `python3` selected Apple's Xcode launcher,
which could not read `/var/select/developer_dir` inside the sandbox. This is not
evidence of an HTTP connectivity failure.

Changed the browser test to request `python3.12` on macOS, matching the existing
native suite and explicitly approved Homebrew installation; Linux keeps `python3`.
Updated the macOS preview example accordingly. No sandbox permission was added.
The four regular preview tests and native strict Clippy pass after this change.
The real browser HTTP round trip still requires a new Terminal run before it can
be reported as passing.

### Terminal report macos-20261022T051314Z.log

The standalone Python change resolved the Xcode launcher failure. All 20 native
macOS tests and two non-network preview tests passed again. The browser test
then detected an unapproved TCP bind succeeding under the preview profile;
therefore the allow-only listener rules did not enforce the advertised bind
restriction. No browser HTTP success is established by this report.

Added an explicit preview-only deny for TCP bind/inbound endpoints outside the
approved localhost ports, retaining the final process-info denial. The existing
outbound IP grant may imply bind permissions, so deny-default plus a narrow
listener allow was insufficient. This explanation is an inference from the
observed bind behavior; the failure lacked the endpoint detail needed to
attribute the specific permitted bind. The test now reports each attempted
endpoint, denial flag and errno using synthetic data before failing. Its
negative assertions are retained. The stricter policy passes the actual SBPL
parser here, then this managed environment rejects sandbox_apply. Four regular
preview tests and strict native Clippy pass; runtime listener enforcement and
HTTP connectivity still require the next Terminal run. No broader host access
was granted, and the failing security test was not skipped or weakened.

### Terminal report macos-20261022T065447Z.log: corrected ingress contract

All 20 native security tests and both non-network preview tests passed. Both
negative bind probes returned EPERM under the explicit-deny policy, but binding
the approved 127.0.0.1 port also returned EPERM. The proposed narrow listener
policy therefore failed its positive control, and is not usable.

Primary implementations document that Seatbelt cannot reliably confine ingress
to loopback/selected ports: Microsoft's mxc Seatbelt backend and Bazel commit
696734cfd3d338d04a885fa65b996ece43fe365c. Replacing further speculative port rules,
preview now denies TCP bind/inbound by default on macOS and requires explicit
`--allow-network-listen` to grant unscoped TCP listener access. This is an explicit
capability opt-in, not a silent weakening. `--port` requires that flag and only
prints the expected URL. The CLI and security docs state the LAN exposure risk
and require configuring the app for loopback without claiming OS enforcement.
Linux retains its documented shared-network behavior. Filesystem, environment,
process-information and synchronization protections are unchanged.

The old negative port/address assertions described an unsupported contract and
are superseded, not treated as passes. A separate real macOS test now verifies
IPv4/IPv6 loopback and wildcard TCP binds are denied WITHOUT approval. The HTTP
round-trip test explicitly opts in, binds its own server to 127.0.0.1, and checks
host-browser access and project isolation; it makes no claim that an opted-in
process cannot bind elsewhere. Four regular preview tests and strict native
Clippy passed after this change. Actual updated denial/HTTP tests require a new
Terminal run; this managed environment cannot establish their runtime results.

## npm executable symlink compatibility (2026-10-22)

A real app's preparation stopped at `node_modules/.bin/acorn` because the copier
rejected all symlinks. Workspace handling now supports a narrow subset: relative
links directly targeting a permitted single-linked regular file also present in
the snapshot. Link text is bounded and read with descriptor-relative readlinkat,
with metadata stability checks; the copier never follows it. Links are recreated
only after regular files have been copied. Absolute/escaping/protected targets,
chains, directory links, interior parent traversal, hard links and special files
remain refused. This is not blanket npm/pnpm/workspace compatibility.

Snapshots record optional link targets (old regular-file records remain readable).
Review renders link targets without target contents, and sync stages/validates
link objects without dereferencing. Added tests cover npm-style copy/target edits,
link add/modify/delete, regular/link replacements and rollback, diff display,
escape/protected/custom-protected/directory/chain rejection and unsafe output
retargeting. All 37 regular Rust tests pass; macOS and aarch64 Linux all-target
strict Clippy pass. Added real Linux/macOS tests execute an npm-style linked
synthetic tool inside the OS sandbox and check original .env exclusion and
isolated editing. Real sandbox results still need the next Terminal/Linux run;
the managed execution environment cannot establish their success.

## Explicit non-web toolchain support (2026-10-22)

Implemented typed read-only SDK approvals for Rust distributions, Go, JDK,
Android SDK and Xcode. Roots/executables are validated before launch, required
tools cannot resolve outside the approved tree, project overlap and broad or
sensitive roots are refused. Linux receives narrow ro-binds; macOS uses separate
validated SDK grants while retaining the original installation-root validation.
Preflight uses the same SDK mounts/grants as execution. Whole SDK contents are
visible by explicit approval and are not filtered like project files.

Added disposable Cargo/Go/Gradle/Android/npm/pip/Python cache variables, private
Rust target artifacts, positional sandbox-only workspace executable launching
(`./gradlew`, `./mvnw`, binaries/scripts), and `tools [--check]` diagnostics.
Version checks execute inside the sandbox with no provider credentials and
suppressed tool output, and make no full-build compatibility claim. Common
mobile signing and package-manager credential filenames are now mandatory
project exclusions. Docs and standalone Android/Rust/iOS configuration examples
include SDK prerequisites, read-only/mutable-cache limitations and migration
notes for retained sessions containing newly protected files.

Validation: 43 regular tests pass, including toolchain config strictness,
private-cache generation, unsafe workspace program paths/arguments, SDK layout
validation and escaping/writable executable rejection, and mandatory credential
protections. Metadata-only tools detection also verifies project scripts are not
executed and manifest contents are not printed. Strict native and aarch64 Linux
all-target Clippy pass. Added an
ignored real OS test with a synthetic SDK: required fake compiler runs inside,
SDK writes and original .env reads must fail, project script arguments stay
literal, output remains isolated, and private caches are cleaned. This test is
included in test-macos.sh and the Linux integration selection. It was attempted
in this managed macOS session and refused at sandbox_apply with EPERM; it is NOT
a passing OS security result. Run from Terminal before relying on these changes.
No real SDK credentials, model calls or host SDK configuration changes were used.

No full Android/iOS vendor build, Emulator/Simulator, USB/adb service integration,
GUI session or release-signing workflow was tested or implemented. No broad
Mach-service, host home/cache, Keychain or device grant was added to make these
work. Those platform workflows remain explicit future work, not implied by
successful metadata or version checks. See docs/toolchains.md.

### Passing Terminal report macos-20261022T091626Z.log

Inspected the supplied report from macOS 26.5.1 arm64 (25F80), Rust/Cargo 1.99.1,
with explicit /opt/homebrew approval. All check groups passed: formatting,
43 regular tests, strict Clippy, 21 real native security tests, four real preview
tests and the synthetic SDK isolation test. Failed check groups: zero.

This establishes the report's actual OS results for internal npm-style link
execution, ChatGPT credential-copy isolation, host process-data exclusion,
preview HTTP reachability after explicit listener approval, default TCP bind
denial, preview output rejection/review/application, read-only SDK enforcement,
literal project-script arguments, original .env exclusion and isolated output.
The SDK test uses a synthetic compiler; it does not establish real Rust, Go,
Java, Android or Xcode build compatibility. Linux was not exercised by this
macOS run. No model requests or real provider credentials were used. Existing
mobile service/signing/GUI limitations remain unchanged.

### Xcode license visibility correction

The first real unsigned Simulator-SDK build in retained session gjaxHh stopped
at the Xcode license prompt. Host `xcodebuild -license check` and
`-checkFirstLaunchStatus` both returned zero; the root-controlled global
acceptance record matched the selected Xcode license. No license was accepted
or system setting changed during diagnosis.

The explicitly configured iOS toolchain now permits read-only access to the
single `/Library/Preferences/com.apple.dt.Xcode.plist` record after ownership,
permissions, regular-file, size and link-count validation. Other toolchains do
not receive this permission. `tools --check` also runs the noninteractive license
check. Host user preferences and signing credentials remain excluded.

All 45 regular tests and strict native and aarch64 Linux all-target Clippy pass.
The new opt-in real Xcode test was attempted, but this managed environment
refused the mandatory sandbox preflight with `sandbox_apply: Operation not
permitted`. It is not a passing OS result or a successful full iOS build. Run
`AGENTVAULT_TEST_XCODE_APP=/Applications/Xcode.app bash scripts/test-macos.sh
--runtime-root /opt/homebrew` from Terminal, then retry the retained preview.

### CoreSimulator framework visibility correction

The next supplied preview output passed the license check but reported dyld
blocking `/Library/Developer/PrivateFrameworks/CoreSimulator.framework`. This
installed dependency lives outside the approved Xcode application bundle.
The iOS-only profile now grants read/executable-map access to that specific
root-controlled bundle, with directory/ancestor and contained executable
validation. It grants no Simulator services, user data, writes or broader
Developer directory access. Missing installations are not repaired automatically.

All 46 regular tests, strict native and aarch64 Linux all-target Clippy, and the
native build pass. The opt-in Xcode test now includes a fixed synthetic C helper
that loads the real framework inside the sandbox, plus an unconfigured-profile
negative read control. The test was attempted here and refused at mandatory
preflight (`sandbox_apply: Operation not permitted`), before the helper ran.
No real framework-loading or complete iOS build success is claimed. Run the
optional test from Terminal before retrying the actual preview.

### Report macos-20261022T102846Z.log and external framework dependencies

The supplied Terminal report passed formatting, 46 regular tests, strict Clippy,
21 real macOS security tests, four real preview tests and the synthetic SDK test.
One check group failed: the real Xcode test passed the license check but its
framework-loading helper was blocked loading `ROCKit.framework`. This is not a
successful complete Xcode test or iOS build.

Inspection of installed Mach-O dependency tables with `/usr/bin/otool -L`
identified ROCKit and DVTDownloads as CoreSimulator's external dependencies under
`/Library/Developer/PrivateFrameworks`. Both now receive the same iOS-only,
root-controlled, read/map-only validation and grant. Nested dependencies inside
CoreSimulator already fall within its bundle; other inspected dependencies are
in existing system runtime roots. No dynamic arbitrary-dependency approval,
broader directory grant, Simulator service access or installation change was
introduced. Profile tests cover conditional grants for all three bundles, and
the real Xcode test retains the framework-load positive control with unconfigured
profile negative read controls. The corrected real test must be rerun from
Terminal; managed sessions prohibit nested Seatbelt launches here.

### Report macos-20261022T103212Z.log and workspace discovery

Inspected the full report: all check groups passed, including the real Xcode
license/framework-loading test after adding the two external dependencies. It
records 46 regular tests, 21 real macOS security tests, four preview tests, one
synthetic SDK test and one real Xcode compatibility test. No complete app build
was performed by these tests.

The subsequent real project build reached workspace discovery but failed with
`is not a workspace file`, alongside blocked Simulator service warnings. Checked
both host and retained session gjaxHh: contents.xcworkspacedata parses as Workspace
XML and its two relative project references exist in both copies. The error is
not explained by a missing workspace copy. Simulator service access is still
unsupported; no host service permissions were added based on these warnings.

Added a separate opt-in synthetic workspace diagnostic with host/sandbox controls,
relative/absolute path comparisons, bounded runtime/output and PID-filtered
best-effort denial collection. Native/Linux strict all-target Clippy and script
syntax validation pass. Attempted the diagnostic here, but mandatory Seatbelt
preflight was refused by the managed session. Its actual workspace discovery
result therefore requires a Terminal run and remains unverified.

### Workspace diagnostic macos-xcode-20261022T103647Z.log

The fixed empty workspace succeeds outside the sandbox (exit zero), but both
relative and absolute workspace discovery fail inside (exit 66). The recorded
denials include CoreServices lookup, CoreDevice framework reads, and repeated
public account-record reads. These observations do not yet identify the minimal
necessary permissions. The captured denial output reached its bound and omitted
later records; an available log command does not establish a complete trace.

The diagnostic now isolates service logs from noisy account/volume metadata
records, reports truncation, and compares three narrow temporary permission
candidates using separate private homes. Production permissions remain unchanged.
Native and Linux strict Clippy validate compilation; candidate OS results must
be obtained from Terminal because the managed environment blocks Seatbelt.

### Workspace diagnostic macos-xcode-20261022T104054Z.log

The complete captures show the host control passing and production relative and
absolute path checks failing with exit 66. All three prior candidates fail too:
CoreServices alone, the literal public account record alone, and their combination.
Separated denial logs now show blocked `com.apple.lsd.mapdb` and `lsd.modifydb`
lookups; output was not truncated. The earlier candidates did not establish a fix.

The selected iOS profile now adds only the exact LaunchServices mapdb lookup,
which Android's build sandbox source separately identifies as an xcodebuild
dependency. No modifydb, account record or additional CoreServices/Simulator
permission was promoted from the diagnostic. Unit tests check opt-in scoping,
absence of modifydb/Simulator grants and the final process-data denial. The real
Xcode test now also checks empty-workspace recognition and its returned JSON.
This compatibility correction still requires actual Terminal verification; a
successful model session or complete iOS build is not inferred from compilation.

### Actual app build reaches unsupported Interface Builder integration

The subsequent WorldTableTennis build reaches `CompileXIB` for
StandingsResultsHeader.xib. Its ibtoold output reports disconnected
CoreSimulatorService/simdiskimaged, unreadable profile locations and finally
`iOS 26.5 Platform Not Installed`. Read-only host metadata inspection finds an
`iOS 26.5.simruntime` bundle under CoreSimulator/Volumes (alongside other versions).
Bundle presence does not certify a functioning runtime, but downloading another
runtime is not an established fix for this sandboxed service failure.

This is an observed full-build compatibility failure, not an XIB syntax diagnosis
or successful mobile build. Native Xcode checks to date cover license state,
framework loading and workspace discovery, not Interface Builder/runtime service
support. The CLI and toolchain guide now explicitly identify XIB/storyboard builds
that require CoreSimulator as unsupported. No service/device-directory permissions
or unsandboxed fallback were added. Safe Simulator service/helper integration
remains unimplemented and requires its own security design and actual OS tests.

### Private Cocoa home and fixed-XIB investigation

Set CFFIXED_USER_HOME to the private HOME on macOS, with a mandatory preflight
environment equality check and an actual NSHomeDirectory check in the optional
Foundation/framework helper. Apple CoreFoundation source prioritizes this
override ahead of the account home. This reduces incorrect host-home use; it is
not a new access-control or Simulator-service isolation claim.

Added a separate opt-in fixed-XIB diagnostic using one explicitly approved
installed runtime. It compares production/direct compiler paths and private
runtime-catalog/root experiments while denying known Simulator services, then
checks original-project canary exclusion under each candidate's exact profile.
Shared diagnostic helpers now collect observed descendant PIDs for best-effort
denial filtering as well as enforcing bounded output and command duration.
No production runtime-directory or Simulator-service permission was introduced.
Actual compilation results require Terminal; this managed session prohibits
nested Seatbelt and therefore cannot certify this blocker resolved.

Verification for this change: 46 regular tests, strict native/aarch64 Linux
all-target Clippy, native build, formatting and diagnostic shell syntax pass.
The installed-runtime diagnostic passed SDK-path validation, then was refused
at mandatory sandbox preflight with `sandbox_apply: Operation not permitted`.
No host or sandbox XIB compilation ran in that attempt; no candidate was
promoted to production. Explicit runtime approval trusts root ownership and
macOS admin-group writers, matching the SDK trust model; other group/world
writes, set-ID directories and paths outside the system runtime volumes refuse.

### Fixed-XIB report macos-ibtool-20261022T145325Z.log

Inspected the supplied report. The host synthetic control exits zero and produces
an artifact. Production, direct compiler, private-runtime-catalog and explicit
runtime-root candidates all exit one without artifacts. All original-project
canary checks pass; these are direct access checks, not service containment
proof. No capture is truncated, and no service-blocked candidate succeeds.

The private-runtime catalog reaches a SimLaunchHost-arm64 lookup and attempts
to load the selected runtime's liblaunch_sim.dylib through that service; sandbox
lookup denial prevents it. Inspection of the installed service binary identifies
library-loading and spawn operations, so it cannot be treated as a passive
metadata dependency. No Simulator endpoint permission was granted based on this
result. The tested environment/catalog methods do not resolve the blocker.

The proposed next boundary is a separate clean macOS build worker, documented in
docs/ios-build-isolation.md. That worker is not implemented or tested; the choice
of deployment is pending. No VM, host account, runtime installation, host policy
change or unsandboxed project execution was performed. Full iOS/XIB build support
remains unverified and unavailable in the native production policy.

The developer subsequently specified native execution in the current login
account, excluding VM, separate-Mac and separate-account workers. The proposed
worker is not an accepted next step. Same-account helper/IPC confinement remains
unimplemented and unverified; no Simulator service permission or fallback was
added to satisfy this constraint. Repeating the unchanged fixed-XIB diagnostic
is not expected to resolve the recorded failure.

### Explicit helper-connection experiment

The service-blocked fixed-XIB failures do not establish the safety or
compatibility of a service-enabled policy: that policy had not been tested.
Added an explicit `--test-helper-connections` diagnostic mode for Apple silicon,
using the same fixed XIB and fresh private workspaces. It compares launch-helper
only permission with the narrowly named Simulator helper set, while preserving
the client filesystem restrictions and final process-info denial. Shared host
helper use is disclosed; no production policy, generic agent permission or
host launchd configuration is changed. Compile success and direct client canary
denial, if observed, will not establish service-mediated secret protection.

Native and aarch64 Linux all-target strict Clippy, formatting and shell syntax
checks pass. The explicit helper mode was attempted in the managed session and
refused at mandatory Seatbelt preflight, before any compiler/helper experiment
ran. Real compatibility and helper-mediated containment remain unverified.

### Helper-enabled report macos-ibtool-20261023T033639Z.log

The host control succeeds. Production and all service-blocked candidates fail.
Both `private-runtime-launch-helper` and `private-runtime-simulator-helpers`
exit zero and produce compiled nib artifacts. All direct original-project
canary checks pass. Thus, allowing only SimLaunchHost-arm64 with the selected
runtime/catalog is a working fixed-XIB compatibility candidate on the reported
host; broader Simulator endpoint access was not necessary for that test. The
final production-policy failure is expected because no candidate was promoted.
The other-denials capture is truncated; candidate outputs/results are not.

This does not certify service-side containment or a complete real application
build. Added an explicitly opted-in service-mediated canary test: a fixed dylib
constructor reads a synthetic host marker, with host-readable and sandbox-denied
direct controls, followed by a private CoreSimulator API request to load that
dylib via SimLaunchHost. A host read through the service marks the candidate
unsafe. Rejection or unsupported private API/signature is inconclusive and
cannot be mistaken for a successful containment test. Even an observed service
denial covers only that operation, not all helper spawning paths.

Native/Linux strict all-target Clippy and diagnostic shell syntax pass. The
updated service test requires a real Terminal run; no production policy was
changed or host credentials used.

### First service-mediated canary result

The supplied Terminal output passes both direct controls: host loading produces
the readable marker and sandbox loading produces the denied marker. The service
request returns an error and no constructor marker. This is inconclusive: no
service-mediated canary read was observed, but neither execution nor confinement
of that constructor was established. It is not a passing security test or proof
that the tested service permission is unsafe.

The probe now prints bounded NSError domains/codes/descriptions and underlying
errors, reports the private method's return result, and adds an explicitly
approved real Apple liblaunch_sim library as a positive service control. The fake
library uses the expected liblaunch_sim filename. The runtime approval is now
required in the standalone service test as it already was in the wrapper script.
No production policy was changed. Real updated probe results require Terminal.

### Observed platform-library validation

The next supplied Terminal result establishes more than an unspecified request
failure: the real Apple library is accepted with no error, the direct sandbox
canary remains denied, and the synthetic dylib is rejected with NSPOSIXErrorDomain
code 88 and an explicit platform-binary/non-platform-file signature mismatch.
No constructor marker is produced. The arbitrary non-platform library-load path
is blocked in this observed configuration. This is not a proof that all
service-side reads or spawned processes inherit the client's restrictions.

Renamed the scoped test to `simulator_service_rejects_nonplatform_library` and
added a bounded structured helper result. It requires a successful real-library
control, a returned payload request, explicit rejection with the observed error
classification, and no constructor marker. A generic error or absent marker
alone stays inconclusive; a readable canary remains an unsafe-candidate failure.
The old broad confinement test name/expectation was not justified by its probe.
The new assertions require a Terminal run; the supplied output establishes the
underlying observed rejection, not execution of the newly edited assertions.

### Service report Boolean serialization regression

The next supplied run still showed the correct platform-signature rejection but
the Rust assertion did not classify it. Reproduced the cause locally using
Foundation: boxing the C comparison `@(error != nil)` serializes as JSON integer
`1`, not Boolean `true`; serde_json correctly treats those as distinct types.
The failure was in the test's structured report, not evidence of an OS policy
change or unexpected constructor execution.

Fixed the actual helper serializer to use NSNumber numberWithBool explicitly for
all three fields. Added a non-Simulator regression that compiles and executes the
actual helper's early self-test path: accepted, signature-rejected and generic
error cases must contain real JSON Booleans, and generic errors must not qualify
as signature rejection. That regression passes in this managed session. Compiler
HOME/CFFIXED_USER_HOME/TMPDIR are private so it does not depend on inaccessible
host temporary/cache paths. The ignored real service test now prints only the
parsed Boolean fields to make future classification problems visible.
Production helper permissions remain unchanged. The full service interaction
still requires Terminal; no broader helper confinement result is inferred from
the serializer regression.

After the correction, all 47 regular tests pass, including the actual native
Foundation serializer regression. Strict native and aarch64 Linux all-target
Clippy also pass. Real ignored OS/service tests were not counted as passing in
this managed run; the updated service assertion still requires Terminal.

### Passing native service library-rejection test

The supplied Terminal run of `simulator_service_rejects_nonplatform_library`
passes (one passed, zero failed, one regular serializer test filtered out).
The real Apple library control is accepted without error; the host direct
constructor reads its synthetic marker and the sandbox direct constructor
cannot. The service-mediated payload request is rejected by platform code-signing
validation, returns accepted=false/error=true/nonplatform_signature_rejected=true,
and produces no constructor marker. Captures are not truncated.

This establishes the specific non-platform library-rejection behavior on the
tested installed runtime and host. It does not establish that arbitrary child
processes started through the accepted Apple runtime inherit the requesting
agent's filesystem restrictions, nor that every Simulator API is confined.
Production helper access remains disabled; broader process/service containment
testing and actual project-build verification remain outstanding. Repeating this
unchanged library test is unnecessary unless related code or platform state
changes.

## Xcode navigator registration

`xcode-register` has metadata tests separate from OS sandbox and Simulator tests.
Coverage includes insertion-only edits, preserved build phases, duplicate
references, localized/version groups, quoting, missing trailing commas,
malformed/unsupported projects, cycles, protected paths, symlinks, hard links,
traversal, batch rejection, repeat registration and retained-session review/apply.
Apple `plutil -lint` accepts the generated fixture on this Mac. A separately
selected temporary metadata copy of WorldTableTennis-iOS also passes insertion,
idempotence and `plutil` checks. The actual user project and retained session
were not modified by these tests. These checks do not certify GUI refresh,
target membership, a complete iOS build, or helper process confinement.

## Native iOS session/spawn authorization experiment

Added a focused opt-in launch-helper test and
`scripts/test-macos-simulator-spawn.sh`. It attempts fresh-session creation as
an ordinary client and a fixed synthetic child launch in an unknown session,
after loading the approved Apple runtime library. Host and direct-sandbox
controls use only a synthetic canary. The test requires explicit identity and
unknown-session rejection errors; generic connection, loader or executable
failures cannot count as authorization evidence. Unexpected session acceptance
closes its binding port and skips the spawn. Existing sessions are never
enumerated or addressed.

The helper compiles, and reflection-only inspection matches the installed
private Objective-C ABI without opening a service connection. All 63 regular
tests pass, formatting passes and strict native all-target Clippy passes.
The final helper cleanup change also passes the focused regular tests.

The real experiment was attempted in this managed session. Report
`macos-simulator-spawn-20261023T092037Z.log` records refusal at mandatory
production preflight: `sandbox_apply: Operation not permitted`. No session or
spawn request was made, and this is not an authorization-test pass. Run the
new script in Terminal to obtain that evidence. Full unsigned
WorldTableTennis-iOS builds, existing-session ownership, alternate service
operations and service-mediated child confinement remain unverified. Production
agent/preview permissions remain unchanged.

### Supplied native result: unknown-session rejection and a service assertion

`macos-simulator-spawn-20261023T093833Z.log` records both synthetic child
controls passing, the approved Apple library accepted, and the unknown-session
spawn rejected with `com.apple.SimLaunchHostService.RequestError`, code 3,
`Bad or unknown session`. PID remains -1 and no child marker exists. This
establishes that specific negative request; it does not test a known existing
session or helper-spawned child confinement.

Session creation returned POSIX code 53 (connection interrupted), so the test
correctly did not count it as an NSError authorization rejection. The test's
expectation that the identity guard returns an NSError was wrong. The matching
local crash report `SimLaunchHost.arm64-2026-10-23-150837.ips` records the
service's SIGTRAP at the request time, 2026-10-23 15:08:35 +0530. Its first
service caller frame has image offset `0xf630`; its arm64 image UUID is
`19d8d6a0-1b6f-3b8e-b2e2-28a8f49e37ce`, matching `dwarfdump --uuid` on the
installed service. Disassembly shows that return address immediately follows
the Swift assertion call whose message is `Only CoreSimulatorService can start
a session`, in `SimLaunchHost_arm64/Client.swift`, line 161. This correlates
this crash to the caller-identity guard. An arbitrary service interruption or
a different crash is not equivalent evidence.

Removed session creation from the native test and renamed it
`simulator_service_rejects_unknown_session_spawn`. The wrapper keeps its
existing filename, but now makes only the unknown-session spawn request after
the real-library control. The assertion requires the structured error domain,
numeric code and description; a regression covers the supplied connection
interruption and malformed/error-mismatched reports. No repeat of the crashing
session-creation request is needed. The original combined test remains a failed
test run; it has not been relabeled as passing.

These observations do not justify general agent/build-script access to the
launch-helper endpoint. Full builds remain blocked pending a constrained
Interface Builder integration and real application-build validation. No
production permissions were changed.

## Initial constrained XIB compiler implementation (2026-10-26)

Added the experimental developer-invoked `xib-compile` command and
`interface_builder` compilation module. One permitted retained XIB is copied
into a private compiler workspace; only the fixed approved `ibtoold` receives
the selected read-only runtime and exact launch-helper endpoint. Other approved
agent runtimes and SDKs are excluded. The profile denies networking and retains
the final process-data denial. Requests have typed bounded options, no command
or plugin proxy, and no host authentication. Publication exports only validated
artifact bytes, stages them outside compiler access and uses a no-replace
descriptor-relative rename into the locked retained session.

All 71 regular tests pass. New tests exercise argument/entity rejection,
traversal, symlinks/hard links/FIFOs, protected artifacts, immutable output
export, no-clobber publication, entry budgets including empty directories,
diagnostic bounds and compiler deadlines. Formatting and strict native and
aarch64 Linux-target all-target Clippy pass. The temporary dependency cache
and host standard library needed restoration; crate archives were verified
against Cargo.lock, and the standard-library archive against its official
published SHA-256. No dependency or lockfile changes were required.

The new real compilation test was selected with explicit Xcode and iOS 26.5
runtime approval. It reaches the mandatory production preflight and is refused
with `sandbox_apply: Operation not permitted` in this managed session. No XIB
compiler/helper request was sent and no native compile success is claimed.
`scripts/test-macos-xib-broker.sh` runs the exact compiler-profile host-canary
and active-TCP denial checks, followed by real compilation and publication,
from Terminal. These new ignored native tests have not passed here.

This implements one developer-invoked compilation operation, not a complete
IPC broker or `IBC_EXEC` integration. Storyboard compilation/linking, hostile
resource-reference/service-mediated containment tests and the full unsigned
WorldTableTennis-iOS build remain outstanding. See [the XIB broker](xib-broker.md).

### Fixed canary-helper compilation prerequisite

The supplied `macos-xib-broker-20261026T072917Z.log` reaches the native
preflight but fails while compiling the fixed C canary helper, before any
compiler-profile filesystem/network assertion or XIB compilation. Reproduced
the same direct Xcode clang invocation with a cleared environment locally:
`fatal error: 'arpa/inet.h' file not found`. The toolchain clang executable
needs an explicit Mac SDK sysroot in this environment.

The native test now resolves the MacOSX SDK inside its selected developer
installation and passes `-isysroot`. The actual guard source is shared from
`tests/support/xib_guard.c`; a regular regression builds it through the same
helper under a cleared environment, then executes only its usage-error branch
(no file reads, socket operations or service connections). That regression
passes locally. Compilation failures now print bounded escaped compiler
diagnostics, and the file/network controls print their failed operation and
errno instead of returning only a silent exit code.

This fixes the reproduced test prerequisite failure. The revised native
compiler-profile assertions and real XIB compilation still require Terminal;
the original supplied failure is not a passing isolation or compilation result.

### Compiler networking grant conflict

The next supplied report, `macos-xib-broker-20261026T073349Z.log`, passes the
fixed helper compilation and both host-file denial controls but records a
successful TCP connection from the compiler profile (`result=0`). The test
correctly fails. Its `errno=1` is stale after a successful connect and is not
evidence of denial. The original compiler profile inherited the ordinary
agent's operation-specific outbound IP/resolver socket allowance and appended
only a network-family denial; that composition did not revoke the allowance
on the tested host.

The Seatbelt builder now selects an explicit network mode. Agent and preview
profiles receive their existing outbound IP and exact resolver socket grant.
The offline compiler profile never includes those grants and explicitly denies
network-outbound, network-inbound, network-bind and the network family. Both
real XIB compilation and its exact-profile canary test use the new offline
command path. The real TCP assertion remains unchanged and still requires an
explicit permission error against a live listener.

A regular regression inspects commands produced by the actual builder to
ensure offline profiles contain no network allows, while agent/preview retain
their expected grants and the final process-data denial stays in place. This
static check does not replace the native connection test. Native verification
of the revised profile and real XIB compilation still requires Terminal.
All 73 regular tests, formatting and strict native/aarch64 Linux-target
all-target Clippy pass after this correction.

### Passing native constrained XIB compilation

The supplied `macos-xib-broker-20261026T112203Z.log` passes both selected real
tests on macOS 26.5.1 arm64 with explicit Xcode and iOS 26.5 runtime approval.
`compiler_profile_denies_host_canaries_and_ip_networking` passes its host
positive controls and requires explicit permission denial of both synthetic
host files and an active TCP listener under the exact offline compiler profile.
`isolated_compiler_produces_a_nib_without_applying_source` then uses the actual
constrained compilation implementation, produces a real NIB, validates its
artifact bytes and publishes into a separate workspace while leaving the
original project source unchanged. Each test reports one passed and zero failed.

These results establish the tested standalone single-XIB path. They do not
certify arbitrary service-mediated operations, hostile resource references,
storyboard compilation/linking, the retained-session CLI end to end, an
`IBC_EXEC` IPC bridge or the full unsigned WorldTableTennis-iOS build. Repeating
these unchanged tests is unnecessary unless related code or platform state
changes. The next integration step is a bounded wrapper/broker protocol for
Xcode's Interface Builder requests, with separate validation of that boundary.

## Initial IBC_EXEC integration (2026-10-26)

Implemented experimental `ios-build` with a fresh filtered copy or an existing
locked retained session. It selects an unsigned Debug Simulator build, private
DerivedData and a per-build `IBC_EXEC` wrapper. Build scripts use the ordinary
sandbox; only isolated compiler jobs receive the approved runtime/helper
connection. The controller captures its executable/runtime selection in host
memory and never reads those decisions from shared state.

Typed version, XIB, storyboard and storyboard-link requests use authenticated
versioned file frames under the disposable home. Frames carry validated bytes
and resource basenames instead of host input/output paths. Metadata, payload,
file/path counts, queue entries, requests and reply times are bounded. The host
uses pinned no-follow reads, rejects malformed/authentication/size/path errors,
stages inputs and returns validated output bytes. The client pins the build
root without following ancestors and publishes there with no clobber. Partial
plist data is preserved and dependency-info records remap isolated paths to
the copied source/build paths. Shutdown cancels in-flight work and joins the
broker before private-directory cleanup. Source edits remain unapplied.

Regular tests now exercise actual file transport with protocol-only handlers,
including authentication, request symlinks, malformed/overflowing/truncated
frames, cancellation, typed option rejection, byte publication, output-root
substitution and dependency remapping. These handlers do not simulate or claim
OS compiler/service confinement. The Apple `plutil` check accepts the new
synthetic app project metadata.

The new native typed-job test was explicitly selected with Xcode/iOS 26.5
approval. This managed session refuses its mandatory startup preflight with
`sandbox_apply: Operation not permitted`, before the version/compile requests.
No new native integration success is inferred from the older standalone XIB
report. `scripts/test-macos-ib-bridge.sh` runs real version/XIB/metadata/
storyboard/link operations, a complete synthetic Xcode app through `IBC_EXEC`,
then optionally the selected real project. It stops at the first failing stage.
The fixture and WorldTableTennis-iOS builds remain unverified until Terminal
results arrive. See [the bridge and native runner](ios-build.md).

During local option validation, the installed Xcode 26.5 `ibtoold` reports
`Unknown argument '--generate-dependency-info'` on a version-only query. The
adapter therefore generates ld64-style records for its declared staged inputs
and validated outputs rather than forwarding this unsupported flag. A regular
regression checks those records through the remapper. It does not claim a trace
of all SDK files read internally; each build uses fresh private DerivedData.

After the bridge, pinned client publication and declared-dependency changes,
all 82 regular tests pass. Formatting, shell syntax, Apple project metadata
lint, and strict native/aarch64 Linux-target all-target Clippy also pass. The
two new ignored native tests are still awaiting Terminal results.

### Passing typed jobs; Xcode wrapper path-alias failure (2026-10-27)

The supplied `macos-ib-bridge-20261027T031203Z.log` passes
`typed_jobs_produce_xib_storyboard_link_and_auxiliary_outputs` (one passed,
zero failed, 7.36 seconds). This exercises actual version output, XIB
compilation, partial plist/dependency records, storyboard compilation and
storyboard linking through the constrained compiler implementation.

The subsequent complete Xcode fixture fails during IBC_EXEC version discovery,
before resource compilation. The client rejects its own private-home binding:
the build log uses both `/var/...` and `/private/var/...` spellings. Reproduced
the exact same client error locally by querying a canonical private-home bridge
through its system alias. No actual Xcode/OS sandbox is required for that
adapter regression.

The controller now canonicalizes its newly created home and verifies the two
root-owned macOS system aliases. The client maps only the fixed `/var` and
`/tmp` prefixes to `/private/var` and `/private/tmp`, before binding checks and
input/output comparisons. It does not follow arbitrary build-path symlinks or
perform new readlink operations inside the sandbox. Settings/queue and build
root traversal stay no-follow. Regressions cover alias-based version queries,
aliased source/artifact/side-file paths, prefix boundaries, traversal rejection
and the existing substituted-DerivedData refusal.

The reproduced alias regressions pass locally. The Xcode fixture and real
WorldTableTennis build remain unverified. The runner's new `--from-fixture`
option resumes those stages without repeating the unchanged, passing typed
compiler jobs; the selected/skipped stages are explicit in its new report.
All 84 regular tests, formatting, shell syntax and strict native/aarch64
Linux-target all-target Clippy pass after the alias correction.

### Xcode wrapper ancestor-read failure (2026-10-27)

The supplied `macos-ib-bridge-20261027T041157Z.log` gets past the alias check
but still fails IBC_EXEC version discovery with `Operation not permitted`.
The client's no-follow traversal opened every ancestor with `O_RDONLY`, while
the main build profile permits only metadata access to ancestors outside its
private roots. This is a likely cause of the new error; that native report does
not identify the failing syscall.

Traversal now uses search-only directory descriptors (`O_SEARCH` on macOS,
`O_PATH | O_DIRECTORY` on Linux), with `O_NOFOLLOW` and `O_CLOEXEC` on every
component. Only the final permitted root is opened for reading. The sandbox
policy is unchanged. Operation-specific error contexts identify any remaining
failure. New regular tests exercise a real execute-only ancestor, with a
read-open negative control, and reject both intermediate and final symlinks,
parent traversal and relative roots. Native Xcode fixture and real application
builds remain pending Terminal validation.

After this correction, all 86 regular tests, formatting, and strict native and
aarch64 Linux-target all-target Clippy pass locally. These checks do not certify
the native sandbox traversal or the complete Xcode build.

### Complete fixture passes; real app needs system content (2026-10-27)

The supplied `macos-ib-bridge-20261027T042044Z.log` passes the complete
synthetic unsigned app build through IBC_EXEC (`BUILD SUCCEEDED`; one native
fixture test passed in 10.67 seconds). This validates the search-only traversal
correction on the tested macOS/Xcode configuration.

The following WorldTableTennis-iOS build reaches resource compilation but fails
on `GroupIndividualStatsView.xib`. The actual ibtool error requests a `System
content for IBCocoaTouchFramework-seventeenAndLater` execution context, then
fails to create a private SimDeviceSet because CoreSimulatorService is blocked.
This is distinct from the earlier wrapper errors. General service access has
not been granted.

Static inspection of the installed Xcode 26.5 compiler shows its default
`LNEPhase0` local encoder and the accepted `LNEPhase2` compiler option. A
version-only query with `--compilation-mode-for-ios LNEPhase2` succeeds and
returns version XML. Bridge compile jobs now select `LNEPhase2`, retaining
unsupported-property preflight and fallback, rather than the separate
`LNEForce` mode. Compiler diagnostics preserve line breaks while escaping other
control characters. Neither the client's accepted arguments nor sandbox grants
are expanded.

The native typed-job test and complete fixture now use a richer synthetic XIB
with nested stack views, empty/default labels, fonts, image views, and named
and system colors. This is a feature regression fixture, not a reproduction
proven to trigger the identical failure. These changed native tests and the
actual application must be rerun; the encoding-mode change is an unverified
candidate fix for the real resource failure.

All 86 regular tests, formatting, strict native/aarch64 Linux-target all-target
Clippy, and the richer fixture's XML/unique-ID checks pass locally. Native
resource compilation remains unverified with the changed mode.


### Remaining system-content dependency and explicit compiler opt-in (2026-10-28)

`macos-ib-bridge-20261027T043735Z.log` passes typed compiler jobs and the complete
synthetic app with LNEPhase2, then fails the real application on
`PaginationView.xib`. The document contains an animating large activity indicator
with a named color. Its system-content execution context cannot create a private
SimDeviceSet because CoreSimulatorService is denied. The encoder change alone
did not fix the real build.

Added the explicit `ios-build --allow-compiler-simulator-services` compatibility
option. Only the separately sandboxed compiler receives the service lookups;
the ordinary agent/build-script profile is unchanged. Host-captured authority
cannot be selected through requests or shared bridge settings. The default keeps
the explicit denials and explains the option on this particular execution-context
failure. Shared Apple services have host account authority; direct compiler
restrictions do not certify service-mediated confinement or helper cleanup.

Regular regressions cover CLI opt-in/defaults, rejection of authority fields in
untrusted jobs and wrapper arguments, preservation of base restrictions and the
final process-info denial. The native canary test checks both profiles when
explicitly selected; the validation runner then uses that selection for typed
jobs, the fixture and the selected app. The fixture now covers an animating large
activity indicator with a named color. Native validation of this new mode is
pending: this managed session rejects nested `sandbox_apply`, and direct
compiler probes cannot access SimLaunchHost. No native success is claimed.


Validation for this change: all 88 regular Rust tests passed, with the real
sandbox tests ignored as intended; formatting, shell syntax and strict native
all-target Clippy passed. The explicit native run is recorded in
`macos-ib-bridge-20261028T172839Z.log`. It stopped at the mandatory ordinary
sandbox probe (`sandbox_apply: Operation not permitted`), before either profile's
canary assertions or resource compilation. Run the full command in
[ios-build.md](ios-build.md#native-validation) from Terminal to verify the new
compiler mode and actual app. A prerequisite failure does not validate the fix.
