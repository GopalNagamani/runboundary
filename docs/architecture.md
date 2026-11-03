# Architecture and implementation decisions

AgentVault is a Rust executable using clap. Cobra and go.mod belong to Go; this implementation uses Cargo.toml and Cargo.lock. Linux uses Bubblewrap; experimental native macOS uses Seatbelt through sandbox-exec. Windows sandboxing is unsupported. See macos.md for the distinct native boundary and unverified release gates.

The trusted computing base comprises the host kernel, non-setuid administrator-installed Bubblewrap on Linux or Seatbelt on macOS, AgentVault, its dependencies, and the administrator-managed runtime mounts. The agent, its subprocesses, project code, and returned workspace are untrusted. The invoking developer, host administrator, host processes with the same UID, and concurrent malicious host writers are outside this boundary. This is filesystem confinement, not a VM boundary.

## Execution path

1. Canonicalize the explicitly selected project (default: current directory; no Git-root guessing).
2. Read a single-link regular agentvault.yaml using descriptor-relative no-follow operations. Reject unknown fields and policies that weaken the mandatory baseline.
3. Resolve the requested executable only in administrator-managed installation directories. Resolve symlinks then check root ownership, executable mode, and every ancestor for group/other write permission. Reject setuid/setgid installations.
4. Traverse the project through directory descriptors. Test exclusions before opening file contents. Reject special files and hard links. Read symlink text without following it; support only relative, direct links to permitted regular files in the snapshot, and recreate them after copying all regular files. Reject outside/protected targets, chains and directory links. Compare inode/device/mode/link count/timestamps/size before and after reading. Refuse observed races and resource-limit overruns.
5. Create a 0700 temporary parent and an isolated workspace child. The parent is never mounted; the agent cannot expose the temporary workspace to other host users merely by changing the mounted child permissions. Copy regular files with owner read/write and original owner executable bit. Record hashes and identities of permitted files only.
6. Start a probe through the same mandatory platform builder used for agent execution. Probe host-path exclusion and workspace writing; Linux additionally probes capabilities and no_new_privs. Report only what the probe checked.
7. Start the executable with inherited stdin/stdout/stderr and a new sandbox terminal session. Signal handlers forward INT/TERM/HUP/QUIT/WINCH to the Bubblewrap supervisor; status uses ordinary exit code or 128+signal. Full interactive agent behavior, job control, terminal resizing, and signal forwarding remain release-gating Linux validation items.
8. Wait for Bubblewrap; scan output through the same no-follow traversal, this time rejecting any protected output. Display added/modified/deleted regular files. Directory-only changes are not synchronized; permissions normalize to 0600/0700 for files.
9. Retain changes for `review SESSION --diff`, then `review SESSION --apply`. Alternatively `run --apply` explicitly authorizes the session's changes in advance. Never apply automatically after a nonzero agent exit.

## Linux runtime namespace

A fresh mount namespace exposes only read-only /usr, /bin, /lib, /lib64 when present, selected DNS/NSS and CA certificate configuration, a new /proc in a private PID namespace, a minimal Bubblewrap /dev, private /tmp and /home/agent, and the copied /workspace. Root mount is remounted read-only; the workspace, temporary directory, and private home remain separate writable mounts. /sys, /run, /var, host /home and /root are absent. Runtime-directory/project overlap is rejected. Runtime directories MUST contain no host secrets or unrelated projects: their entire read-only contents are exposed, including /usr/local. This compatibility tradeoff needs deployment review.

User/PID/IPC/UTS namespaces are mandatory. Nested user namespaces are disabled and asserted disabled. All capabilities are dropped. PR_SET_NO_NEW_PRIVS and close_range(CLOSE_RANGE_CLOEXEC) run before exec; failure refuses startup. There is no inherited-descriptor fallback for older kernels. Only descriptors 0, 1, 2 are intentionally retained after validating that they are terminals, pipes, or /dev/null; regular files, sockets, and other devices on standard streams refuse startup. Bubblewrap --new-session mitigates controlling-terminal input injection; no full terminal-output sanitization or seccomp profile is implemented.

Networking is shared with the host. No claims of network DLP, localhost-service isolation, syscall filtering, resource containment, or protection from kernel exploits are made. No host Unix sockets or agent configuration directories are mounted. Landlock is deferred: this MVP depends on the tested mount-namespace boundary rather than adding an unverified second mechanism.

## Change application

A retained review record lives outside the sandbox in .agentvault and contains hashes, original file identities, and the private workspace location. Review previews show only permitted files, with terminal controls escaped and a 64 KiB preview cap. Host baseline conflicts refuse application. Output is revalidated immediately before staging. Protected paths, links, special files, and path traversal refuse the entire sync.

All writes use pinned parent descriptors and no-follow traversal. Replacement originals are renamed into a private recovery directory; staged files are installed with atomic no-replace renames. A durable intent journal precedes each operation. Synchronous errors attempt rollback; original bytes remain available in recovery storage. Multi-file synchronization is NOT globally atomic. Crash/power failure, filesystem errors, or a malicious concurrent same-UID host writer require manual recovery. See recovery.md. The sandbox cannot race host synchronization because it has no host project mount. Concurrent ordinary developer edits detected by snapshot checks cause refusal; pause editors/build tools during approval.

## Audit visibility

Structured JSONL records cover policy acceptance, probes, launch requests, exits, rejected output, retained workspaces, and synchronization. They never include command arguments, token values, file contents, or raw backend errors. Bubblewrap does not provide per-filesystem-denial events. A launch request is not proof the executable initialized; local isolation probes and process exit are separate events. The audit log is developer-owned and is not tamper-proof against the host owner or administrator.

Backend reference: [Bubblewrap manual](https://manpages.debian.org/bookworm/bubblewrap/bwrap.1.en.html), including namespace, nested-user-namespace, mount, capability, and terminal-session options. AgentVault must still verify these options on the deployed host; documentation is not execution evidence.

## Native macOS extension

The shared backend dispatcher requires an explicit configuration/host match.
The Linux builder retains its namespaces and hardening; Seatbelt uses a
separate deny-default profile with parameterized paths, scoped system reads,
private writable directories, and explicit additional runtime approval. Both
reuse the existing workspace snapshot, policy, review, and journaled sync code.
The macOS probe uses an actual readable host canary outside the workspace and
checks that reading it and listing the original project fail while private
writes work. No provider credentials are supplied to probes. See macos.md
for descriptor closure, process sessions, broker policy, networking, credential
cleanup, deprecated interface status, and differences from Linux.

### Retained-session preview

The preview command loads the same review record and acquires a persistent
per-session nonblocking flock shared by preview/review/apply. It validates the
workspace location, loads current policy, rejects unsafe output, allocates fresh
private home/temp siblings, probes the configured sandbox, and launches the
requested trusted executable with filtered environment and inherited terminal IO.
macOS preview denies TCP bind/inbound by default; explicit
`--allow-network-listen` instead grants TCP listeners without address/port
confinement. The final process-info denial is preserved. `--port` describes an
expected URL only. Linux uses the existing shared-network Bubblewrap setup.
After execution, private directories are removed and the workspace is rescanned.
The retained record and original host baseline remain unchanged, so subsequent
review/apply includes both agent edits and preview-generated files. There is no
automatic application or inference that passing tests approves a session.

### Toolchain bindings

Optional typed toolchain config validates canonical SDK roots and required
executables without running them. Backend selection constructs read-only SDK
bindings, deterministic compiler/JDK/SDK variables, and PATH entries independent
of the host shell. Both preflight and actual commands receive the same SDK
visibility. Bubblewrap ro-binds selected trees; Seatbelt adds SDK read/map grants
through a separate validated path from ordinary Homebrew installation roots.
Private cache directories are siblings of the workspace inside the disposable
home. Project scripts are executed through positional `exec "$@"` by a trusted
shell within the backend. `tools --check` executes version checks under this OS
boundary; it never treats metadata detection as full toolchain compatibility.
