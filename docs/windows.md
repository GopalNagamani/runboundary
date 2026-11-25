# Native Windows port: first foundation

The current RunBoundary CLI uses Unix file descriptors, permissions and process
APIs. It does not yet compile or launch agents natively on Windows. A Windows
Rust installation printing Hello World verifies the compiler/linker, not an
RunBoundary security boundary. WSL verifies the Linux backend, not a Windows one.

The first Windows-specific module, `internal/platform/windows_paths.rs`, defines
relative-path syntax for the future Windows filesystem backend. It has no Unix
imports or external dependencies and can be tested independently with rustc.
It rejects drive-relative/absolute paths, UNC and NT/device namespaces, traversal,
alternate data streams, reserved DOS devices (including extensions and superscript
digits), trailing dots/spaces, invalid characters and oversized components.
It preserves valid case and Unicode without claiming case-insensitive identity.
Tilde spellings are conservatively unsupported until short-name checks exist.
These rules follow Microsoft's Windows filename/namespace documentation:
https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file

Run on Windows from the transferred RunBoundary source directory:

```cmd
powershell -NoProfile -File scripts\test-windows-foundation.ps1
```

The same standalone foundation check now runs in the `windows-foundation` CI
job on `windows-latest`. This keeps Windows path-rule coverage on a native
Windows filesystem; it does not compile or validate the RunBoundary CLI there.

This compiles and runs **eight lexical unit tests**, records the results under
`test-results/windows-foundation-*.log`, and removes the temporary test executable.
It does not change execution policy, firewall rules, account permissions or host
security controls. If local policy blocks the script, do not bypass an
organization's policy; the same tests can be compiled/run directly:

```cmd
rustc --edition=2021 --test internal\platform\windows_paths.rs -o "%TEMP%\runboundary-windows-path-tests.exe"
"%TEMP%\runboundary-windows-path-tests.exe" --nocapture
```

The module is not wired into the existing Unix copier. Path checks alone cannot
stop a process from reading secrets. The Windows CLI must remain unavailable
until an actual mandatory OS backend has been implemented and tested.

Remaining stages, in order:

1. Implement Windows handle-relative traversal, identity and link checks. Reject
   reparse points, junctions and unexpected hard links; enforce private ACLs and
   safe creation/rename/recovery. Resolve short-name/case aliases through actual
   filesystem handles, including policy matching. Lexical validation is only
   an initial input check, never a substitute for race-safe filesystem access.
2. Implement a Windows process backend. Prototype AppContainer/LPAC with narrow
   filesystem grants and explicitly scoped provider networking. Use Job Objects
   for process lifetime management, restricted handle inheritance and a clean
   environment. Job Objects alone do not establish filesystem isolation.
3. Run real Windows deny/allow, descendants, original-project, credential,
   inherited-handle, startup-failure and adversarial-filesystem tests. Validate
   actual token restrictions and accessible resources; never report mere API
   availability as verified isolation.
4. Add interactive terminal integration, explicit credentials, agent version
   compatibility and provider sessions, then preview and journaled review/apply.

Windows test-machine setup is separate from Windows backend implementation.
The development Mac and a Windows machine can share SSH connectivity while
this assistant environment still lacks direct network or authenticated access.
