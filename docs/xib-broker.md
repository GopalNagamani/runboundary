# Experimental constrained XIB compilation

`xib-compile` implements the first broker operation: one UTF-8 XIB from a
pending retained session is compiled in a separate temporary Seatbelt sandbox.
The separate experimental [`ios-build` integration](ios-build.md) now routes
Xcode's `IBC_EXEC` requests, including storyboard jobs, through a typed file
bridge; its native integration tests remain unverified. The standalone supplied
`macos-xib-broker-20261026T112203Z.log`
passes both the exact compiler-profile host-file/TCP denial test and real
isolated compilation/publication of the synthetic XIB. This verifies the tested
single-XIB path; the actual application build remains unverified.

The command accepts source bytes, a simple optional module identifier and a
numeric deployment target. It builds a fixed `ibtoold` command; it cannot proxy
shell commands, arbitrary flags, compiler/plugin paths or environment variables.
Input is limited to 8 MiB. DTD/entity declarations, NUL and non-UTF-8 input are
rejected. Input and output paths must be permitted workspace-relative `.xib`
and `.nib` paths. Files are read through pinned directory descriptors without
following links; the retained session stays locked during compilation.

Only the separate compiler receives the approved read-only Xcode/runtime and
`com.apple.CoreSimulator.SimLaunchHost-arm64` connection. Other configured agent
runtimes/SDKs are excluded. Its home, runtime catalog, caches and output are
private; IP/Unix networking and other known Simulator helper endpoints are
denied. No provider authentication, host home, signing assets, project scripts
or session-creation requests are imported. A successful ordinary sandbox
preflight is mandatory before sending any compiler request.

The compiler has a 60-second deadline, bounded diagnostics and process-group
cleanup on completion, interruption and errors. Outputs are treated as untrusted:
regular single-linked files only, at most 64 MiB total and 4096 entries, with
bounded nesting. Links and special files fail. Validated bytes are copied into
a controller-only staging directory, checked against protected-path policy and
published with a no-replace rename. The compiler's writable directories are
never moved into the session. Existing output is never overwritten.

From the original project, with Xcode already approved in `runboundary.yaml`:

```sh
runb xib-compile SESSION \
  --simulator-runtime "/Library/Developer/CoreSimulator/Volumes/YOUR_VOLUME/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS YOUR_VERSION.simruntime" \
  --input Views/MyView.xib --output Views/MyView.compiled.nib \
  --module YourApp --deployment-target 17.2
```

The output parent must already exist. Compilation changes only the retained
workspace. Review and apply remain separate operations; this command does not
register the generated NIB in Xcode or replace the project's XIB build rule.
A compiled NIB is a generated artifact, not proof of a full application build.

Run real tests from Terminal:

```sh
bash scripts/test-macos-xib-broker.sh \
  --xcode-app /Applications/Xcode.app \
  --simulator-runtime "/Library/Developer/CoreSimulator/Volumes/YOUR_VOLUME/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS YOUR_VERSION.simruntime"
```

The tests must demonstrate explicit host-canary and active TCP listener denials
under the exact compiler profile, and produce an actual NIB through the new
compilation path. Managed sessions on this Mac refuse nested `sandbox_apply`;
that is a prerequisite failure, never a passing isolation result.

The shared Apple service has its own authority. Restricting its caller does not
prove all service-mediated operations inherit those restrictions. The previous
library and unknown-session tests cover only their stated requests. Hostile XIB
and resource-reference tests, service-mediated confinement, native storyboard validation,
native validation of the new bounded `IBC_EXEC` bridge and the actual unsigned
WorldTableTennis-iOS build remain required before claiming full build support.
