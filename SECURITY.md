# Security policy and threat model

The native macOS process-data disclosure found during development has been
fixed for the tested APIs and configuration. The generated profile retains
its startup self-information rule and appends a final process-info family
denial. The supplied `macos-20261021T171714Z.log` records all 15 native tests
passing on macOS 26.5.1 arm64, including direct and descendant argument/environment
read denials through KERN_PROCARGS and KERN_PROCARGS2 with positive controls.
The temporary CLI block is removed; mandatory sandbox startup checks remain.
Live authenticated agent sessions and broader attack paths remain unverified.

RunBoundary is an experimental development MVP, not a production security product. No production-readiness or completed Linux sandbox-validation claim is made.

On macOS the exact `/private/var/run/mDNSResponder` socket is an explicit
outbound exception for OS DNS resolution. Other host Unix sockets remain
outside the allowed boundary. This DNS exception was the minimal successful
candidate in a real DNS/HTTPS comparison; it grants no filesystem subtree
access and does not weaken the final process-data denial. Outbound networking
can transmit permitted data and credentials; it is not data-loss prevention.

## Intended boundary

An untrusted coding agent, project code, and descendant processes receive a filtered copy of a project and selected administrator-managed runtime files. They must not directly access excluded project files, unrelated host home directories, the original project, host credential directories, or host Unix sockets through the sandbox filesystem. On Linux, mandatory Bubblewrap mount/user/PID namespaces enforce this boundary. The experimental macOS backend uses a separate Seatbelt policy, described below. Policy patterns alone are not a sandbox.

Protected path names are classified without reading their file contents during discovery/copy. Agent output is untrusted and cannot be applied to protected paths. Hard links and special files are rejected. Relative symlinks are supported only when their direct target is a permitted regular file present in the copied snapshot. Link text is read with readlinkat and recreated without following it; absolute/escaping/protected targets, directory links, chains and interior traversal are rejected. Inherited privileged file descriptors above stderr are marked close-on-exec; descriptors 0, 1, 2 must be terminals, pipes, or /dev/null. Regular files and sockets on standard streams are rejected before launch. Setuid Bubblewrap and root execution are refused. Startup failures never execute the requested command outside the sandbox.

## Trusted components and exclusions

Trust the Linux kernel, Bubblewrap, RunBoundary and its dependencies, the host administrator, invoking user, and exposed runtime files. Host administrator/root and malicious same-UID host processes are outside scope: they can inspect or alter RunBoundary directly. A malicious concurrent host writer can invalidate assumptions between checks; descriptor-relative traversal prevents symlink escapes, but it is not a defense against an attacker who already controls the invoking account. Stop ordinary editors/build processes before synchronization. Detected metadata/content changes fail closed.

The complete read-only /usr, /bin, /lib, /lib64 trees can be visible. These directories must contain only deliberately approved system runtimes, not secrets or unrelated projects. Selected DNS, NSS, and TLS trust configuration is also exposed. Writable system-runtime directories are not a supported deployment. Home-installed agents and their login caches are not automatically imported.

Unrestricted shared networking includes localhost and host-reachable services. A vulnerable or unauthenticated host service could expose host information over TCP despite filesystem isolation. No network isolation, egress policy, exfiltration prevention, seccomp filtering, CPU/memory/disk quotas, or defense against kernel vulnerabilities is provided. Nested user namespaces are disabled; this does not replace syscall filtering. Terminal output from an interactive agent remains untrusted; review previews escape controls but the live agent's terminal stream does not.

**Secrets already present in permitted source files, agent-visible environment variables, model prompts, or approved authentication credentials cannot be protected by RunBoundary.** File renaming or copying a secret into an otherwise permitted path can defeat name-based selection when performed by the trusted host user before preparation. Review output now heuristically redacts common credential assignments, provider token prefixes, bearer values, and private-key blocks. This reduces accidental display but is not complete content-based secret detection; it does not prevent the agent from reading or transmitting permitted content.

Approved OPENAI_API_KEY and ANTHROPIC_API_KEY values are visible to agents and descendants. They may read, persist, or transmit them. They are never intentionally included in RunBoundary arguments, audit records, or diagnostic output. Agent-controlled terminal output may print credentials; RunBoundary does not claim to redact the live terminal stream. Model-provider authentication and networking are not verified by a local presence check.

Synchronization is a journaled sequence with backups, not a cross-file atomic transaction. Ordinary failures attempt rollback. `runb recover` can restore an interrupted version-2 transaction when paths still match its journal; conflicts, legacy journals, and I/O failures may require manual recovery. Review records/audit logs are not tamper-proof against the developer. Recovery files and retained workspaces can contain sensitive permitted code; clean them up explicitly. Empty directories, ACLs, xattrs, sparse layout, and most original permission bits are not reproduced. Workspace limits are 64 MiB/file and 1 GiB total; no runtime write quota exists.

Bubblewrap does not supply an exhaustive denied-operation log. RunBoundary audits observed lifecycle/policy/sync decisions, not every denied filesystem access. No Landlock enforcement claim is made; it is deferred pending a tested design that adds value beyond the mount namespace.

## Validation and reporting

See docs/validation.md for the exact checks run and outstanding release gates. Passing portable Rust tests is not proof of Linux enforcement. Run the ignored OS tests on a supported Linux host and validate live Codex/Claude versions before deployment.

For vulnerability reports, provide a minimal reproduction using synthetic credentials, OS/kernel/Bubblewrap versions, policy, and observed behavior. Do not publish real secret values. This repository has no configured private reporting endpoint; request a private maintainer contact before sharing an unpublished exploit. Do not assume that an unconfigured GitHub security advisory workflow exists.

## Experimental native macOS backend

macOS uses a separate deny-default Seatbelt policy through sandbox-exec. The
Linux namespace/capability/no_new_privs statements above apply only to Linux.
There is no private macOS mount/PID namespace or complete descendant-lifetime
guarantee. Native process permissions and daemon/API exposure differ from
Linux. See [macOS security boundary](docs/macos.md) before opting in.

Homebrew access requires explicit read-only runtime approval. All files in
that approved tree become readable; it must contain no unrelated secrets.
Explicit macOS runtime approval trusts its owner and admin-group writers;
world-writable and non-admin group-writable paths are refused. Original host
home, credential directories, Keychain brokers and host Unix
sockets are not broadly exposed. Only named system Mach lookups and bounded
hardware/OS sysctl categories are allowed. Provider credentials remain visible
to agents; private session directories are removed before retaining workspace
edits, but an agent can persist credentials in permitted source files.

The native implementation builds and has portable tests. The managed
development session refuses sandbox_apply, so the real macOS security suite
and live agent sessions must pass from an ordinary Terminal before native
security guarantees are relied on. Apple's deprecated/private interface and
future OS compatibility are additional risks. There is no fallback to an
unsandboxed process or automatic permission widening.

## Experimental constrained XIB compilation

The experimental developer-invoked `xib-compile` command creates a separate
compiler sandbox with one explicitly approved runtime and the exact
`com.apple.CoreSimulator.SimLaunchHost-arm64` connection. Agent and preview
profiles do not receive that permission. Requests contain one staged XIB and
bounded typed options, not commands or executable/plugin paths. The compiler
has private directories, networking denial, a deadline and bounded diagnostics;
only validated regular-file artifact bytes return to a retained session, with
no overwrite or automatic apply. This is an unverified native compilation
integration: direct filesystem controls do not prove confinement of shared
service operations. See [the XIB broker boundary and tests](docs/xib-broker.md).

The experimental `ios-build` command routes Xcode's Interface Builder and asset
catalog tasks through per-build wrappers and bounded authenticated file frames in the
private home. Authentication does not make build-script callers trusted: the
host independently validates every typed request and stages supplied bytes.
Executable/runtime choices are captured in host memory; shared state cannot
select host commands or input/output paths. Partial plist and dependency outputs
return as validated bytes. The sandboxed client publishes only within private
DerivedData, and broker shutdown cancels active compiler jobs. Localized
compilation accepts bounded locale identifiers plus companion strings bytes;
caller paths never reach the host compiler. Reads use the same no-follow build
roots, each strings file is limited to 8 MiB within the combined input budget,
and duplicate/case-colliding locales are rejected. Storyboard intermediates
package translations as bytes and locale identifiers; raw Apple strings-path
manifests are rejected at the link boundary. The host validates each package
and regenerates the path manifest using fixed locations in the new compiler
sandbox. Optional link locale directories are preserved and validated. The host
chooses all staging paths and revalidates every declared input. The October 30
report records passing typed localized jobs and the prior Xcode fixture.

Asset compilation and symbol generation now use the same isolated fixed
compiler, with a host-selected `actool` persona. Catalog basenames and typed
options are independently checked; arbitrary personas, environment/plugin
flags, runtime paths and external file specifications are not accepted. Catalog
bytes remain within the existing input/file budgets, no-follow traversal and
protected-path checks. Only regular artifact and requested side-output bytes
return to DerivedData. This expands the document/image parsing and shared Apple
service workloads trusted by this opt-in; it adds no agent/build-script service
grants. Native asset tests and the newly expanded fixture remain unverified. See
[the bridge protocol and limits](docs/ios-build.md).

## Explicit ChatGPT credential import

`--codex-auth-file /absolute/path/auth.json` approves one file-backed Codex
ChatGPT login for this session. This is an explicit exception to credential
exclusion, confined to the disposable home outside the editable project. The
importer uses descriptor-relative no-follow traversal, bounded reads, identity
checks, current-user ownership, private permissions, and a JSON field allowlist.
It rejects API-key logins, symlinks, hard links and special files. It never logs
credential contents. Host configuration and Keychain access remain unavailable.
Imported OAuth credentials, including refresh tokens, are visible to all sandbox
processes and can be transmitted over the network. The copy can be refreshed by
Codex but is never synchronized back. Refresh rotation may require host re-login;
concurrent use of the same credentials is discouraged. Normal cleanup removes
the private home before retaining edits; abrupt termination or machine failure
can leave temporary credentials on disk. Filesystem deletion is not secure erasure.

## Previewing retained workspaces

`preview SESSION -- COMMAND` executes untrusted application/build code with the
same filesystem/process backend, sanitized environment, trusted executable
resolution and mandatory preflight as agent sessions. It imports no provider
credentials and grants no approval. A persistent per-session advisory lock
coordinates RunBoundary preview/review/apply commands; it does not prevent other
host processes from editing files. Retained session paths must name private,
current-user-owned workspace directories with a matching session parent.
Unsafe/protected workspace entries are refused before and after preview.

On macOS, preview explicitly denies TCP bind/inbound operations by default.
`--allow-network-listen` grants TCP listener access without address/port
confinement, and prints that limitation before launch. `--port` only describes
an expected preview URL and requires the explicit listener flag. Seatbelt's
`localhost` filter is not a reliable loopback-only ingress primitive; normal
agent profiles receive no new grants. A server listening on a non-loopback
interface may be reachable from the LAN. This limitation is documented by
[Microsoft's Seatbelt backend](https://github.com/microsoft/mxc/blob/main/docs/backends/seatbelt/seatbelt-backend.md)
and [Bazel's macOS networking change](https://bazel.googlesource.com/bazel/+/696734cfd3d338d04a885fa65b996ece43fe365c).
Do not interpret an app's bind address as OS-enforced network isolation.
The process-information denial remains last in generated profiles.

Linux continues to share the host network and does not enforce listener limits
with either flag. Outbound networking remains unrestricted on both backends;
explicit TCP bind denial in macOS previews may also affect clients that bind
source sockets themselves. Preview can contact host network services and transmit
permitted data; this is not network DLP. Configure servers for loopback and do
not use production credentials or production databases for preview.

Foreground signal forwarding/lifetime limitations of each backend continue to
apply. macOS has no PID namespace or complete orphan-process containment;
malicious descendants that detach can outlive a command. RunBoundary rescans
before synchronization but cannot treat a completed preview as proof of runtime
safety. Users must stop previews and review any generated output before approval.

## Relative regular-file symlinks

Workspace preparation may recreate a relative symlink only after the snapshot
contains its permitted, single-linked regular target. Link text is bounded to
4 KiB, read descriptor-relatively without following it, and checked against
before/after identity metadata. Leading `../` is resolved lexically without
escaping the workspace; absolute paths, interior `name/../` traversal and
protected target ancestors are rejected. Targets may not be directories or other
links. Every path component read during copying still uses no-follow traversal.
No protected target contents are read in order to validate a link.

Snapshots record link type, target-text hash and identity separately from regular
files. Output links are revalidated before preview/sync; review prints link text
rather than dereferencing it. Staging, commit verification and rollback read or
move link objects, never their target contents. A link to an allowed file still
permits agent edits to that allowed file; filesystem secrets cannot become safe
by placing them in an otherwise permitted target. Authentication-file imports
continue to reject all symlinks, independently of workspace link support.

## Explicit SDK and build tool access

Configured `toolchains` approve entire selected SDK/distribution trees read-only
on both backends. Broad/reserved/credential roots, project overlap, untrusted
permissions and required executables escaping the tree are refused. The host
SDK's owner/admin writers are part of the trusted computing base. SDK contents
are deliberately visible and are NOT filtered by project secret patterns.
Approvals must not contain unrelated credentials. SDK path and ownership checks
are not a signature or supply-chain attestation. Tools can execute untrusted
project build scripts under the same OS boundary.

Generated language environment and cache directories are inside the fresh
private home; host toolchain environment, registry/login caches, shell startup,
Maven/Gradle user credentials and signing state are not inherited. Run commands
with explicit provider auth still expose those approved provider credentials to
agent subprocesses; credential-free preview remains preferable for app testing.
Mandatory project exclusions now include common mobile signing keystores,
provisioning files and package-manager credential files. These controls do not
recognize credentials embedded in other permitted files or approved SDKs.

Executable workspace paths (`./...`) use descriptor-relative no-follow validation
and are launched by a trusted shell ONLY inside the sandbox. Arguments are
positional, not shell interpolation. A workspace binary is never executed by the
host for detection or validation. Paths can still change while an untrusted
process runs; the OS boundary remains mandatory, and post-run scanning plus sync
checks still apply. SDK approval does not grant GUI, Simulator, adb/USB, signing
or host Keychain services. Existing unrestricted network access can reach host
network services (including adb when listening); it is not a device firewall.

## Xcode system license record

Selecting the iOS/Xcode toolchain additionally permits read-only access to the
single system acceptance record `/Library/Preferences/com.apple.dt.Xcode.plist`.
It is restricted to a root-controlled regular single-link file no larger than
64 KiB; no user preference domain or entire preferences directory is exposed.
No record is generated, modified, or accepted by RunBoundary. The noninteractive
license check observes actual existing state. Normal non-Xcode profiles receive
no new grant; process-data denial remains the final profile rule.

### Xcode system framework dependency

Only a configured iOS toolchain receives read and executable-map access to
`/Library/Developer/PrivateFrameworks/CoreSimulator.framework` and its inspected
`ROCKit.framework` and `DVTDownloads.framework` dependencies in the same
directory. These are a fixed allowlist, not dynamic dependency approvals. The real bundle
directory, ancestors and contained main executable must be root-controlled;
top-level aliases and escaping executable links are rejected. This trusts the
administrator-installed framework as runtime code, as with the selected Xcode
bundle. No write access, broader Developer tree access, Simulator user data or
Simulator service permission is added. Loading the framework is not proof that
a complete Simulator build or device workflow is supported.

The selected iOS toolchain additionally permits the exact
`com.apple.lsd.mapdb` Mach lookup needed for Xcode's type-based workspace
recognition. This allows access to the LaunchServices mapping interface and
may expose registered application/type metadata, increasing host-service attack
surface. It does not grant the separate `com.apple.lsd.modifydb` endpoint,
Simulator services, host home or user preferences. Endpoint naming does not
prove the service can never disclose data or contain vulnerabilities. The final
process-info denial remains after all iOS compatibility permissions.

On macOS, `CFFIXED_USER_HOME` is fixed to the private home alongside `HOME` so
CoreFoundation home APIs do not deliberately select the host account directory.
This is environment compatibility, not an OS access control: an agent can change
its own environment, and Seatbelt must still deny original-project/host access.
It does not reconfigure shared host Simulator services. The separate opt-in
fixed-XIB diagnostic keeps known Simulator endpoints denied while comparing
direct compilation and selected read-only runtime data; successful diagnostics
must not be interpreted as production Simulator or XPC helper containment.


## Explicit Xcode compiler service access

`ios-build --allow-compiler-simulator-services` explicitly grants the separate
fixed compiler lookup access to CoreSimulatorService (global and XPC names) and
simdiskimaged, alongside its existing SimLaunchHost endpoint. This addresses
resources whose UIKit system-content lookup or asset compilation needs a
Simulator execution context.
The default still denies these services and no automatic fallback enables them.
The host captures this selection before running build scripts; the typed job
protocol, wrapper flags and shared settings cannot increase service authority.
The agent/build-script Seatbelt profile is unchanged.

This is an increased trust boundary, not proof of isolated Simulator operations.
Apple services have host account authority, may read/change shared Simulator
state and create/launch Interface Builder devices and helpers. Service state or
processes can outlive private-directory cleanup. Any process inside the build
can submit validated typed documents, so the opt-in also trusts Apple's handling
of hostile documents and resource references. Direct compiler filesystem and
network restrictions, deadlines and artifact validation remain active, but do
not restrict every operation performed by a service. The October 30 report
records passing direct canary checks for both profiles, typed localized jobs and
the prior fixture with services enabled. The actual app subsequently failed at
asset compilation, which still ran outside that broker. Native validation of
the added asset adapter, the expanded fixture and a complete app build remain
outstanding.
