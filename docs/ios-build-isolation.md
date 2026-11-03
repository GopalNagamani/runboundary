# iOS build isolation: investigation and proposed worker

Status: design for the next implementation, not an available backend or a claim
that full iOS builds work. Native agent launches, retained workspaces and review
remain available. Full Simulator-dependent application builds remain unsupported.

An experimental [single-XIB compilation operation](xib-broker.md) is now
implemented as `xib-compile`. Its exact compiler-profile host-file/TCP denial
and real synthetic XIB compile/publication tests pass in the supplied
`macos-xib-broker-20261026T112203Z.log`. It does not intercept Xcode's build
rules by itself. The separate experimental [`ios-build` command](ios-build.md)
now implements typed `IBC_EXEC` routing, with new native integration tests still
unverified. Full application-build support is not yet established.

Current developer constraint: use the existing Mac and login account; no VM,
separate Mac or build account. The separate-worker proposal below is therefore
not an accepted implementation path for this project. It is retained as an
architectural alternative, not an action plan or a requested installation.

## Native same-account work still required

The tested direct-compiler/private-runtime approaches do not suffice. A native
implementation would need to establish a restricted helper/IPC path and prove
that arbitrary agent requests cannot acquire a host service's broader authority.
It must not grant Simulator endpoints to arbitrary agent/build-script processes
merely because one fixed XIB then compiles. Running a trusted Apple executable
does not itself demonstrate confinement of all work submitted to its services.

A potential broker would need a narrow validated operation protocol, fixed
compiler/runtime identities, private output, bounded resources, and real tests
against path substitution, arbitrary library loading, process launching and
service-side access to host canaries. The initial developer-invoked single-XIB
operation and a typed file IPC bridge are implemented. Native verification of
that bridge remains outstanding, and no private Simulator service namespace
is implemented. The old
bootstrap subset/server APIs in the installed SDK are deprecated; their mere
presence is not evidence of a supported solution on the tested macOS release.
No private-API interposition or unsandboxed helper is shipped as a workaround.

The fixed-XIB diagnostic now also offers a separate explicit
`--test-helper-connections` experiment. Earlier service-blocked failures do not
establish that allowing particular endpoints is impossible or necessarily
unsafe. The new experiment measures compilation compatibility under narrowly
named helper permissions without changing the production policy. Its direct
canary checks are insufficient to certify service-mediated containment; that
requires additional adversarial tests before a production feature can be offered.

This leaves a native iOS build blocker under the requested constraints. It is
not proof that every future same-account design is impossible, and it must not
be presented as a resolved compatibility issue. No further unchanged diagnostic
rerun is needed: a new implementation or confinement experiment is required.

### Next native authorization experiment

The latest helper-enabled report (`macos-ibtool-20261023T033639Z.log`) does
produce the fixed compiled XIB with only the launch-helper candidate, as well
as with the broader helper candidate. Production still fails. The passing
non-platform library test covers library validation, not process spawning.

The focused test loads the approved Apple runtime library and tries to launch
a fixed synthetic child in a fresh unknown session. It never enumerates or
targets existing sessions, creates a session, or boots a device.
Host/direct-sandbox child controls prove synthetic canary access and explicit
permission denial respectively. Generic RPC, loader and executable errors
remain inconclusive; the check requires the service's structured unknown-session
error (domain `com.apple.SimLaunchHostService.RequestError`, code 3).

The first supplied run (`macos-simulator-spawn-20261023T093833Z.log`)
explicitly rejects the unknown-session spawn with that error and produces no
child marker. The previous test also attempted session creation. That request
triggered a fatal caller-identity assertion in the shared service, rather than
returning the NSError that the test incorrectly expected. The crash report and
matching installed binary correlate the assertion to `Only CoreSimulatorService
can start a session`; see the validation record. Session creation has been
removed from the test to avoid repeating that service crash. A connection
interruption by itself is still insufficient authorization evidence.

Run this new experiment from the Mac's Terminal:

```sh
bash scripts/test-macos-simulator-spawn.sh \
  --xcode-app /Applications/Xcode.app \
  --simulator-runtime "/Library/Developer/CoreSimulator/Volumes/YOUR_VOLUME/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS YOUR_VERSION.simruntime"
```

The supplied run establishes the unknown-session rejection; the revised test
without session creation still requires Terminal to execute. This managed
session refuses nested Seatbelt startup with `sandbox_apply: Operation not
permitted`. Even a passing result only covers that request:
existing-session ownership, alternate RPCs, service-side file access and a
complete unsigned WorldTableTennis-iOS build still need validation. No helper
permission is added to the production agent or preview profile.

## Evidence from the fixed-XIB test

The report `macos-ibtool-20261022T145325Z.log` records a successful host compile
with an actual artifact. Production, direct ibtoold, private runtime catalog and
runtime-root environment candidates all fail with `iOS 26.5 Platform Not
Installed`; none produces the compiled artifact. All sandboxed candidates deny
the original-project canary read and listing. Those canary checks do not prove
that arbitrary host services or their helpers would be confined.

The private runtime catalog advances to a request for
`com.apple.CoreSimulator.SimLaunchHost-arm64`, which the sandbox rejects. It
cannot load `liblaunch_sim.dylib` through that service. Read-only inspection of
the installed service binary identifies library loading and spawn operations.
This demonstrates a service dependency in the tested compiler path, not that
granting it is safe, nor that every possible native approach is impossible.

Apple describes XPC services as managed by launchd with their own sandbox:
[Creating XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html).
The agent's Seatbelt profile cannot simply be assumed to govern work submitted
to those services. A private HOME or device set does not establish that property.
The tested environment overrides did not eliminate this dependency; no candidate
permission is promoted to production based on these results.

## Proposed separate macOS build worker

Use a clean local macOS VM or a dedicated clean Mac for Simulator-dependent
builds. A Linux guest cannot run this Xcode workflow. Choice of worker remains a
developer decision; no virtualization software, account or OS image is installed
automatically by the current implementation.

The intended flow is:

1. Validate and lock the existing AgentVault retained session.
2. Export only a freshly validated permitted workspace snapshot. Never transfer
   the original directory, agent authentication, signing assets, host home,
   sockets, shared caches or SSH-agent forwarding.
3. Transfer into a new private worker directory. Use an explicitly pinned worker
   identity. Keep connection credentials in the host controller, outside agent
   and guest-visible environments.
4. Build inside the worker using its own Xcode, installed runtime and Simulator
   services. Treat build scripts and all worker contents as untrusted.
5. Return a bounded build status and selected artifacts through validated paths.
   Treat archives, filenames, links and file contents from the worker as hostile.
   Do not auto-extract arbitrary archives or synchronize build output as source.
6. Keep source review and explicit apply on the development Mac unchanged.
   Destroy the per-build state and verify shutdown/cleanup before reusing a
   worker. Failed or interrupted transfers must preserve the retained session.

A VM must not share host directories, home, clipboard, credential stores or
device bridges with the guest. Installing an app in a clean guest would not
expose the original host filesystem through a guest Simulator service. Network
access remains a separate consideration: a guest can reach services exposed by
the host unless a tested network policy prevents it. This is not network DLP.

A separate Mac is suitable only when it is managed as a build worker without
unrelated developer secrets; it does not make that machine's own secrets safe
from untrusted build scripts. User separation alone is insufficient for original
files readable by other users. A local shell helper outside Seatbelt on the
development Mac is not an equivalent isolation boundary.

## Required acceptance tests before claiming support

- Compile the fixed XIB and a representative real unsigned application.
- Run hostile build scripts and Simulator-launched helpers against host-side
  canaries. Exercise direct reads, subprocesses, services and links.
- Verify that host mounts, authentication, signing keys, sockets and clipboard
  are absent, and test any claimed network restrictions with running processes.
- Reject path traversal, links, special files, oversized output and tampered
  archives or manifests during both transfer directions.
- Preserve meaningful exit codes, enforce deadlines, and test cancellation,
  interruption, worker disconnects and partial-transfer recovery.
- Verify that applying changes still requires review and explicit developer
  approval, independently of worker execution success.

Until a worker is implemented and these real OS tests run, the iOS blocker is
open. The passing native sandbox tests cover their stated controls; they do not
certify this proposed worker architecture.
