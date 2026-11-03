# Toolchains and non-web projects

AgentVault previews execute commands, not just web servers. Command-line tools,
libraries, tests, headless desktop builds and mobile source/build commands use the
same copied-workspace and explicit-approval workflow. SDK exposure is implemented;
full Android/iOS builds have not been certified. Emulator/Simulator services,
USB/device integration, desktop GUI sessions and signing are not implemented.
Windows remains unsupported.

## Configure only what you need

Add selected entries to the existing `agentvault.yaml`; do not replace its
security policy. Paths must be literal absolute paths (no `~` or `$HOME`). These
are examples, not automatic discovery. SDKs must be installed and initialized
before launch. Changing this protected host configuration is developer approval
to expose the entire named SDK tree read-only to agents and preview processes.

```yaml
toolchains:
  rust:
    # A particular installed distribution, not ~/.cargo or the whole ~/.rustup.
    toolchain_root: /Users/YOU/.rustup/toolchains/stable-aarch64-apple-darwin
  go:
    root: /usr/local/go
  java:
    home: /Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
  android:
    sdk_root: /Users/YOU/Library/Android/sdk
  ios:
    xcode_app: /Applications/Xcode.app
```

Remove entries that do not apply. Android requires the explicit Java entry too;
choose a JDK compatible with your Android Gradle Plugin. iOS requires macOS.
On Linux, SDK/JDK locations could be `/opt/android-sdk` and `/opt/jdk-17`.
For Node/Python on macOS, the existing explicit
`sandbox.runtime_roots: [/opt/homebrew]` approval still applies.
SDK roots are independent of those installation roots and work on Linux too.

Approvals reject broad roots, credential directories, project overlap,
world-writable/untrusted ancestors, missing SDK layouts, and required tool
executables whose symlink resolution leaves the approved tree. SDK binaries must
be executable and the root/ancestors owned by root or the approving user;
explicit macOS approval also trusts admin-group writers. A shared `/tmp` SDK is
refused. Never use a writable-by-others SDK or put secrets in an approved SDK.

**All files inside an approved SDK are visible.** Project secret patterns do not
filter SDK mounts. Agents can transmit legitimately visible SDK contents over
the network. This is an explicit trust decision, not a guarantee that an SDK is
secret-free. Credentials in sibling home directories are not imported.

## Check actual sandbox availability

```sh
agentvault --project /path/to/project tools
agentvault --project /path/to/project tools --check
```

`tools` identifies manifest filenames without reading their contents and validates
configured SDK paths. `--check` prepares a filtered copy, verifies actual backend
startup/isolation, and executes compiler/runtime version commands inside it.
For configured Xcode, it also runs the noninteractive `xcodebuild -license check`
inside the sandbox. It never accepts a license. It reports only the checks it ran;
version/license-check success does not certify a build,
SDK platform level, signing, emulator, or a GUI. A detected Node/Python project
with an unavailable corresponding runtime fails the check. Rust, Go and Java project markers also trigger compiler checks when available
in ordinary approved runtimes; otherwise configure their explicit toolchains.
C/C++, Swift and Flutter marker detection remains informational.
Missing optional runtimes are reported unavailable rather than as passes.
Version-command stdout/stderr is suppressed; there are no model calls or imported
provider credentials. Checks can be interrupted with Ctrl-C.

## Preview project scripts and tests

Use the retained AgentVault session ID printed after the agent exits.
A name starting `./` runs an executable regular file from the isolated workspace:

```sh
agentvault --project /path/to/project preview SESSION -- ./gradlew --no-daemon test
agentvault --project /path/to/project preview SESSION -- ./mvnw test
agentvault --project /path/to/project preview SESSION -- ./scripts/test.sh
```

Scripts need owner execute permission in the original project (`chmod u+x gradlew`
before creating the session). Binary executables in the workspace are supported
too. Parent traversal, symlink executables and symlink parent directories are
refused. For a non-executable script, explicitly run the trusted interpreter:
`preview SESSION -- sh ./gradlew --no-daemon test`.
Arguments are passed as arguments, not interpolated as shell code. Workspace
programs are launched only inside the sandbox through a trusted shell.
A project program needing several commands can be invoked through `sh -c` with
a developer-written command string; ordinary arguments remain preferable.

Examples:

| Project | Preview command after `preview SESSION --` |
| --- | --- |
| Node library | `npm test` |
| Python library | `python3.12 -m unittest` (Linux: `python3`) |
| Rust CLI/library | `cargo test` |
| Go CLI/library | `go test ./...` |
| Java Maven | `./mvnw test` |
| Android/JVM unit tests | `./gradlew --no-daemon testDebugUnitTest` |
| Android debug build | `./gradlew --no-daemon assembleDebug` |
| iOS unsigned Simulator-target build | Experimental; XIB/storyboard compilation requiring CoreSimulator is currently unsupported |
| Headless desktop build | The project's CLI build/test command with explicitly approved runtimes/SDKs |

For Xcode, keep derived artifacts in the disposable home so app bundle directory
symlinks do not become synchronization candidates:

The following is an experimental build command, not a supported full-app preview.
The observed WorldTableTennis build reaches `CompileXIB` but Interface Builder
fails with `iOS 26.5 Platform Not Installed` while CoreSimulator connections are
blocked. A matching runtime bundle is present on the host. Installing another
copy of the runtime is not an established fix for this sandbox failure. A
successful license, framework-loading or workspace-discovery check does not
validate Interface Builder compilation, even with `CODE_SIGNING_ALLOWED=NO`.

```sh
agentvault --project /path/to/project preview SESSION -- sh -c \
  'xcodebuild -scheme YOUR_SCHEME -sdk iphonesimulator -derivedDataPath "$HOME/build/DerivedData" CODE_SIGNING_ALLOWED=NO build'
```

The Android/iOS commands are starting points from the official tool workflows,
not certification that every project works in this policy. Install required
Android platforms/build-tools and accept licenses outside AgentVault; SDK writes
are denied, including automatic installation of missing components. iOS build
helpers may need additional narrowly justified platform work that is not yet
implemented. No blanket Mach-service, Keychain, host Library, or home grant is
added for compatibility. Xcode's `DEVELOPER_DIR` is set from the approved bundle;
AgentVault does not run `sudo xcode-select` or change host settings.

Supporting this requires a separately designed and tested Simulator integration.
Simply adding host CoreSimulator Mach endpoints and device directories would
cross the current service boundary. An integration must account for host-service
file access, helper execution, device data and whether work can escape the agent's
restrictions. Current AgentVault does not offer a verified configuration for that
workflow. Changing to a physical-device SDK is not a verified workaround for
Interface Builder's runtime dependencies.

Gradle/build systems sometimes need local TCP even for non-web tasks. On macOS,
explicitly add `--allow-network-listen` before `--` if the task needs listeners.
This permits TCP listeners without loopback/port confinement; configure tools
for loopback and do not assume the OS enforces that address. Linux shares the
host network. A host adb server or other service can be reachable via networking;
absence of a device integration is not network isolation from those services.
AgentVault does not import adb keys, host AVDs, Simulator data, signing keys or
provisioning profiles. It does not connect to devices automatically.

Flutter's mutable SDK cache, pnpm/workspace directory symlinks and many GUI
frameworks still need separate integration. Marker detection is not support for
those workflows, and no automatic policy weakening occurs.

## Caches, credentials and output

Each launch has a fresh home and cache state. SDK variables are generated from
validated paths: `JAVA_HOME`, `ANDROID_HOME`, `ANDROID_SDK_ROOT`, `DEVELOPER_DIR`,
`GOROOT`, and selected Rust compiler paths. Host versions of these variables are
not inherited. npm/pip, Cargo, Go, Gradle and Android user state use private
paths under the disposable home. Host registry tokens, Maven settings, Gradle
user properties, Keychain and shell startup files are not imported.
Private-package builds needing credentials may therefore fail.

Rust target artifacts and Python bytecode caches are kept outside the source.
Those artifacts and all private caches are deleted at normal session cleanup;
run a produced binary within the same preview command if it lives there.
For example: `preview SESSION -- sh -c 'cargo build && "$CARGO_TARGET_DIR/debug/myapp"'`.
This avoids silently synchronizing Rust compiler output to the host.
Other generated workspace output is still included in review. Review may reject
protected paths, unsupported links or existing size/file-count limit overruns.
SDK installation, dependency repair, output exclusions and automatic cleanup of
source-tree build directories are not performed on your behalf.

Project `.jks`, `.keystore`, `.p12`, `.pfx`, `.mobileprovision`,
`.provisionprofile`, `key.properties`, `keystore.properties`, `.npmrc`, `.pypirc`,
`.netrc`, and `.m2/settings.xml` are now mandatory exclusions, including for old
configs. These complement existing protections; secrets embedded in permitted
source/config files cannot be detected reliably by filename policy.
There is no release signing or deployment command. Test a debug/unsigned build;
release credentials require a separately designed and verified boundary.

## Verification

```sh
bash scripts/test-macos.sh --runtime-root /opt/homebrew
# Linux: use the existing Multipass/native integration runner.
```

The native runner includes an actual synthetic SDK test: mount it read-only,
execute its fake compiler plus a workspace script inside the sandbox, reject SDK
writes and original `.env` reads, and verify isolated output/private caches.
No real credentials, SDK downloads or provider calls are used. This tests the
security plumbing, not an Android or iOS toolchain. Run `tools --check` with your
real configuration, followed by the actual build, before relying on compatibility.

References: [Android environment variables](https://developer.android.com/tools/variables),
[Android command-line builds](https://developer.android.com/build/building-cmdline),
[Apple command-line tools FAQ](https://developer.apple.com/library/archive/technotes/tn2339/_index.html),
[Cargo environment variables](https://doc.rust-lang.org/cargo/reference/environment-variables.html).

Existing retained sessions that included a newly protected credential filename
may now fail policy/conflict checks. Start a fresh session; do not weaken the
mandatory exclusions to apply an older credential-bearing snapshot.

## Xcode license status

With `toolchains.ios` configured, Seatbelt grants a literal read-only exception
for `/Library/Preferences/com.apple.dt.Xcode.plist`, the system license acceptance
record. The file must be root-controlled, regular, single-linked and at most
64 KiB; symlinks, hard links or unsafe permissions refuse startup. A missing
record stays absent, allowing Xcode's real setup check to fail. Other system
preferences, host user preferences, signing credentials and Keychain access are
not granted. This observes existing acceptance; it does not fabricate it or
modify system state. Finish genuine first-run setup manually in Xcode on the
host if necessary.

To include the optional real Xcode license/isolation test:

```sh
AGENTVAULT_TEST_XCODE_APP=/Applications/Xcode.app \
  bash scripts/test-macos.sh --runtime-root /opt/homebrew
```

This is explicit read-only SDK approval for the test, requires an already
accepted host license, and never runs sudo or an acceptance command. A passing
license test still does not establish that a full iOS build or Simulator works.

The selected iOS toolchain also allows reading and mapping executable code from
the installed `/Library/Developer/PrivateFrameworks/CoreSimulator.framework`.
Xcode loads this system dependency even for an unsigned Simulator-SDK build.
The bundle must be a real root-controlled directory with root-controlled
ancestors, and its resolved main executable must stay within the bundle. Missing
bundles are not installed automatically; unsafe existing bundles refuse startup.
Its inspected external dependencies `ROCKit.framework` and
`DVTDownloads.framework` in that same PrivateFrameworks directory receive the
same conditional read/map permission and validation. These are fixed entries;
AgentVault does not automatically approve arbitrary dylib dependency paths.
The exception does not cover the rest of `/Library/Developer`, Simulator device
data, host user preferences, or Simulator service connections. The optional real
Xcode test also compiles a fixed synthetic helper and checks that it can load the
framework inside the sandbox. A normal profile must still deny framework reads.

If framework checks pass but Xcode rejects an intact copied workspace, run:

```sh
bash scripts/diagnose-macos-xcode.sh --xcode-app /Applications/Xcode.app
```

This compares discovery of an empty synthetic workspace outside and inside the
production sandbox, using separate private homes and relative/absolute workspace
paths. Each command is limited to 30 seconds; captured output is bounded. It
collects best-effort denial records only for the synthetic sandbox PIDs. It does
not build your project, import credentials, accept licenses, enable Simulator
services, or change the production policy. Failure and missing logs are not
reported as successful compatibility. A passing framework-load test alone does
not establish workspace discovery, compilation or Simulator service support.

The workspace diagnostic also compares three temporary profiles: one exact
`com.apple.CoreServices.coreservicesd` lookup, a literal public `/etc/passwd`
account-record read (not the password database), and their combination. These
apply only to the fixed empty workspace, using fresh private homes per candidate.
They never become production permissions automatically; the process-data denial
remains last in every profile. Logs separate service denials from other records
and filter repeated account/volume metadata noise so it cannot hide later service
failures. Output truncation is reported explicitly. The diagnostic still fails
if the unchanged production profile fails, even if a candidate succeeds.

For the explicitly configured iOS toolchain, Xcode workspace recognition also
receives the exact `com.apple.lsd.mapdb` Mach lookup. The separate
`com.apple.lsd.modifydb` endpoint, CoreSimulator services and host user preference
files remain outside the policy. Mapping LaunchServices can expose registered
application/type metadata and increases the host-service attack surface; this
is not a guarantee against all information disclosure or service vulnerabilities.
The real Xcode test now verifies that `xcodebuild -list -json` recognizes a fixed
empty workspace, in addition to license and framework loading checks. A passing
discovery test still does not establish full build or Simulator compatibility.
The need for this endpoint in xcodebuild is also recorded in
[Android's build sandbox source](https://android.googlesource.com/platform/build/soong/+/79f6f7533/ui/build/sandbox/darwin/global.sb).
Only this specific dependency informs AgentVault's policy; that source's broader
permissions are not imported.

## Interface Builder blocker investigation

The experimental `xib-compile` command now stages one retained XIB in a separate
compiler sandbox and validates its NIB output. See [the XIB broker](xib-broker.md)
for the command, boundary and real Terminal tests. It does not yet replace
Xcode's Interface Builder build rules by itself. The experimental
[`ios-build` command](ios-build.md) now supplies a typed `IBC_EXEC` bridge;
its native integration tests and complete application builds remain unverified.

macOS environments also pin `CFFIXED_USER_HOME` to the private `HOME`.
CoreFoundation can otherwise choose the account database home ahead of `HOME`;
see [Apple's CoreFoundation source](https://github.com/apple-oss-distributions/CF/blob/main/CFPlatform.c).
This redirects cooperating Cocoa APIs; filesystem enforcement remains Seatbelt's
job. It does not create a private launchd namespace or isolate an existing XPC
service. The opt-in real Xcode test checks `NSHomeDirectory()` from a compiled
Foundation helper against the private home.

To investigate the XIB blocker without granting host Simulator services:

```sh
bash scripts/diagnose-macos-interface-builder.sh \
  --xcode-app /Applications/Xcode.app \
  --simulator-runtime "/Library/Developer/CoreSimulator/Volumes/YOUR_VOLUME/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS YOUR_VERSION.simruntime"
```

Select an actual installed runtime bundle. The diagnostic requires a root-owned
directory tree under the system Simulator volumes; explicit approval trusts
macOS admin-group writers but rejects world or other-group writes and set-ID bits;
it will not install or mount a runtime. It uses a fixed synthetic XIB and canary,
not your app, build scripts or credentials. A mandatory production preflight
must pass before any compilation, including the synthetic unsandboxed host
control. The host control is a comparison, never a fallback for project code.

Experiments compare the production compiler, direct `ibtoold`, and direct
compilation using a private runtime catalog and one selected read-only runtime.
Only the latter candidates receive the selected runtime, public system device
types and DeviceKit data; the temporary additions are not saved to production
configuration. The helper mode `IBToolNeverDeque` is used as an experiment, not
a promised isolation mechanism; it also appears in
[Bazel's tool wrapper](https://github.com/bazelbuild/rules_apple/blob/main/tools/xctoolrunner/xctoolrunner.py).
Another candidate tests explicit runtime-root environment variables. Every
default sandboxed candidate explicitly denies the known CoreSimulator service endpoints
and retains the final process-info denial. Direct original-project canary reads
and listing must also fail under each candidate's exact profile.

Commands have a 30-second deadline with bounded output. PID discovery and denial
records are best effort and include observed subprocesses; very short-lived
children and launchd services can be missed. Compilation success, even alongside
the direct canary checks, does not prove complete helper/service containment.
The diagnostic still fails if production compilation fails, even when a candidate
succeeds. Such success supplies evidence for a separately tested implementation;
it does not silently enable a candidate or claim full mobile support.

The supplied `macos-ibtool-20261022T145325Z.log` records that all four sandboxed
compiler candidates fail while the host control succeeds. A private runtime
catalog alone still requests SimLaunchHost, so the tested service-free route
does not resolve this blocker. See [the build-worker investigation and proposed
acceptance tests](ios-build-isolation.md) for the next isolation boundary. It is
a proposed integration, not a currently implemented or certified feature.

To test whether named helper permissions enable compilation on Apple silicon,
append `--test-helper-connections` to the fixed-XIB diagnostic command. This
explicit extra opt-in adds two temporary profiles: one permits only
`com.apple.CoreSimulator.SimLaunchHost-arm64` while retaining the other Simulator
denials; the other permits the exact CoreSimulatorService, simdiskimaged and
SimLaunchHost endpoints. Both retain workspace/host-home exclusions and the
final process-info denial. Public runtime enumeration parents receive literal
read permission, not a grant for all Developer contents. These profiles are
used only with the fixed synthetic XIB; they are not agent-visible settings.

Shared helpers may use or create Simulator compilation state in the host
account; private client HOME values do not establish helper confinement. No
arbitrary project or build script is sent to these experiments. A successful
compile demonstrates compatibility only. Direct canary read denials in the
requesting process do not prove that a helper cannot load code, spawn work or
access host files on its behalf. Service-mediated security tests remain required
before promoting permissions to the normal policy. The existing diagnostic
failure remains meaningful when production compilation fails despite a
successful experimental candidate.

The supplied `macos-ibtool-20261023T033639Z.log` records successful compilation
under both helper-enabled candidates. The smaller launch-helper-only candidate
is sufficient for that fixed XIB. The compatibility failure at the end reports
the unchanged production policy; it does not negate the candidate success.

With `--test-helper-connections`, the script now also runs a service-mediated
canary experiment before compilation comparisons. It compiles a fixed helper
and test dylib, verifies host-readable and sandbox-denied direct controls, then
asks SimLaunchHost to load the synthetic dylib via the installed framework's
private API. Its constructor attempts only the synthetic host canary read and
writes a fixed result marker. The request may be rejected or unsupported on
other SDK versions. Such results are explicitly inconclusive, not security
passes. The service interaction is diagnostic-only; no private API is introduced
into normal agent launches. Script output reports the security and production
compatibility exit statuses separately and runs both even if one fails.

The standalone service test also requires
`AGENTVAULT_TEST_SIMULATOR_RUNTIME=/absolute/path/to/selected.simruntime`.
It uses the contained real Apple liblaunch_sim.dylib as a service positive
control and prints bounded NSError details if loading fails. A rejected fake
payload without a constructor marker remains inconclusive; it is not reported
as successful service confinement. The wrapper supplies this runtime variable
from `--simulator-runtime` automatically.

The current scoped service test is named
`simulator_service_rejects_nonplatform_library`. After a successful real Apple
library control, it can establish the specific observed platform-signature
rejection of the fake library without calling that full service confinement.
The fixed probe writes a small JSON result so the test requires the exact
rejection classification rather than treating an absent constructor marker as
success. Unknown errors or API failures remain inconclusive. This narrows and
corrects the previous broad canary-read test; helper-spawned access is still
outside the demonstrated coverage.

For files created in retained iOS projects that do not appear in Xcode's
navigator, use [Xcode file registration](xcode-files.md). This updates only the
retained project's references; approval and target membership remain explicit.
