# AgentVault

A Rust CLI that launches coding agents in a mandatory Linux Bubblewrap or native macOS Seatbelt sandbox with a copied, filtered project workspace. Apache-2.0 licensed. **Development MVP: 18 portable tests and 11 real Linux sandbox tests pass in the tested Ubuntu Multipass VM. Live Codex/Claude sessions remain unverified; this is not production-ready.**

AgentVault excludes sensitive project paths before copying files and keeps the original project outside the agent’s approved filesystem access. It never falls back to an unsandboxed launch. Filename patterns decide what is copied; Linux namespaces or macOS Seatbelt rules enforce the configured filesystem boundary. The macOS backend does not provide Linux namespace isolation.

## Native macOS (experimental)

The supplied `macos-20261021T171714Z.log` records **22 regular tests and all
15 native macOS security tests passing**, plus formatting and strict Clippy,
on macOS 26.5.1 arm64. Native launches are enabled with mandatory sandbox
preflight. Live Codex/Claude authentication and interactive use remain unverified.

Run `bash scripts/test-macos.sh --runtime-root /opt/homebrew` from Terminal to
reproduce the checks without a VM. This explicitly approves Homebrew reads
for the test runtimes. See the [native macOS guide](docs/macos.md) for setup,
limitations and shell/agent examples, and [validation evidence](docs/validation.md).
`init` selects `seatbelt` on macOS and `bubblewrap` on Linux; a mismatched
existing configuration is refused.

## Linux prerequisites and installation

Use an unprivileged Linux account, Linux 5.11+ (including close_range with CLOEXEC support), enabled unprivileged user namespaces, Bubblewrap 0.8+ with --disable-userns support, and a Rust stable toolchain. Distribution security policies such as AppArmor may disallow user namespaces even when kernel support exists. The real startup probe is authoritative; missing support refuses launch.

On a suitable Debian/Ubuntu host:

```sh
sudo apt-get install bubblewrap build-essential pkg-config python3 nodejs
cargo build --release --locked
# Optional: install the CLI, not the agents, as an administrator-managed executable.
sudo install -m 0755 target/release/agentvault /usr/local/bin/agentvault
```

Install Codex or Claude Code and their complete runtime dependencies in root-owned, non-group/world-writable system runtime directories under /usr, typically /usr/local. User-home, nvm, Homebrew, ~/.cargo, ~/.local, and native agent installations stored under the host home are deliberately unsupported. An npm launcher resolving into /usr/local/lib/node_modules is compatible with the mount layout; live version compatibility still needs testing. The executable and every resolved ancestor must be root-owned and have no setuid/setgid or group/other write bits. Do not run AgentVault using sudo.

The Rust CLI uses **clap**, since Cobra is a Go library. Cargo.toml is the Rust package manifest. No rs.mod file or Go wrapper is needed.

## Usage

AgentVault does not require a model API key. Authentication belongs to the
agent and its selected provider. Local or self-hosted models without
authentication can run without credential flags; explicitly approved API keys
and file-backed ChatGPT login are optional integrations. Host login caches and
configuration are never imported automatically.

To use the command name `agentvault` directly, install it once from this
repository (no sudo):

```sh
cargo install --path . --locked
```

Ensure Cargo's installation directory (normally `$HOME/.cargo/bin`) is on your
shell's PATH. Then run commands from your original project's directory; the
current directory is the project root, so no `--project` or `$AV_BIN` is needed:

```sh
cd "/path/to/your/project"
agentvault review SESSION_ID --review
agentvault review SESSION_ID --apply
agentvault preview SESSION_ID -- npm test
```

`--review` is an alias for `--diff`. Review shows changes; `--apply` is explicit
approval. Applied sessions no longer have pending review records. When running
from another directory, continue to supply `--project /path/to/your/project`.

```sh
cd your-project
agentvault init
# Supply credentials through your existing secure environment setup.
agentvault doctor --agent codex --auth-env OPENAI_API_KEY
agentvault run --auth-env OPENAI_API_KEY -- codex
agentvault doctor --agent claude --auth-env ANTHROPIC_API_KEY
agentvault run --auth-env ANTHROPIC_API_KEY -- claude
agentvault audit
```

`init` detects protected path names without opening their contents. It refuses to overwrite an existing configuration; remove or edit it explicitly. The current directory is the project root unless `--project /absolute/path` is supplied. The configuration must exist in that selected directory.

Doctor checks actual sandbox startup and local filesystem isolation before reporting success. A credential-presence check does **not** verify provider login or complete agent compatibility. `run` can also launch a trusted system executable for diagnostics, e.g. `agentvault run -- sh`. No host PATH search, host home mounting, automatic login-directory mounting, or unsandboxed compatibility fallback is provided.

Agent terminal input/output is inherited, restricted to terminals, pipes, and /dev/null. Regular-file or socket standard streams are refused; use a pipe and `tee` for log redirection. Namespace/session and signal behavior must be tested with the particular agent version before relying on interactive workflows. Host authentication is never imported automatically. Choose explicit API-key approval with --auth-env, or approve one file-backed ChatGPT login with --codex-auth-file (see below). These credentials are visible to the agent and its descendants for the duration of the session and may be transmitted or written by them. Do not approve production application secrets.

For new files missing from an Xcode navigator, see [Xcode file registration](docs/xcode-files.md).

For experimental compilation of a single retained XIB in a separate compiler
sandbox, see [the XIB broker](docs/xib-broker.md). Full iOS builds remain unverified.
The experimental [`ios-build` command](docs/ios-build.md) now provides typed
`IBC_EXEC` routing for unsigned Simulator builds; native integration validation
is still required.

## Reviewing and applying edits

By default the original project is unchanged. Changed workspaces are retained under a private temporary parent; AgentVault prints a session identifier:

```sh
agentvault review SESSION --diff
agentvault review SESSION --apply
```

The preview prints only permitted files; text lines are escaped to prevent terminal control injection. This is a before/after preview rather than a minimal unified diff. It never reads protected host files. Binary and large file previews are summarized. The developer must review the code, not only filenames, before approval. `--apply` is explicit developer approval; it does not imply that generated code is safe.

For advance approval of a session, use `agentvault run --apply --auth-env OPENAI_API_KEY -- codex`. It summarizes changes and applies only after a zero exit code. Prefer the two-step review workflow. Approval is never inferred from agent output. Unsafe/protected outputs reject synchronization. Host changes since preparation cause refusal. No Git repository is required.

Application retains original files and a durable journal under `.agentvault-recovery-*`. It attempts rollback on synchronous failure, but multi-file application is not globally atomic and crash recovery can require manual work. Read [recovery instructions](docs/recovery.md). After review, explicitly remove retained temporary workspaces, review records, and recovery directories you no longer need; they can contain sensitive permitted source code. Unchanged workspaces are cleaned up automatically. Agent edits to empty directories, directory modes, and metadata other than the owner executable bit are not synchronized.

## Security model and limitations

Read [SECURITY.md](SECURITY.md) and the platform-specific [macOS guide](docs/macos.md) before use, along with [architecture](docs/architecture.md), [configuration](docs/configuration.md), and [validation status](docs/validation.md).

On Linux, the system-runtime mounts expose their full read-only contents. They must not contain secrets or projects; /usr/local is not assumed to be secret-free merely because it is a runtime directory. Projects overlapping exposed runtime directories are refused. Home-installed agents are not supported by weakening this rule.

AgentVault cannot protect secrets already present in permitted source files, allowed environment variables, model prompts, or approved authentication credentials. Networking is enabled and unrestricted, including reachable host services: an agent can transmit everything it can legitimately read. This is not network DLP. The kernel, host administrator, same-UID host processes, runtime installations, and the developer approving changes must be trusted.

## Tests

On a Mac with Multipass installed, use the [automated Linux VM test guide](docs/multipass.md): `bash scripts/test-multipass.sh`. It copies only the build/test source and writes reports to `test-results/`.

Portable tests, formatting, and lint checks:

```sh
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

Real security integration tests are explicitly ignored by default and show their prerequisites. On a supported **unprivileged Linux** host with Bubblewrap, Python 3, Node.js, and system shell runtimes:

```sh
cargo test --locked -- --ignored --nocapture --test-threads=1
```

These ignored tests actually invoke Bubblewrap; they do not mock filesystem permissions. Explicitly running them on an unsupported host fails with a prerequisite error rather than reporting false success. The normal test command does not establish Linux security guarantees. Kernel restrictions inside Docker/CI can prevent tests; use a Linux VM with the required namespace support. The supplied CI workflow runs the real suite and fails when isolation is unavailable; it does not weaken host policy automatically.

No Codex or Claude Code version is currently certified. See the [version validation matrix](docs/validation.md) and record exact agent, kernel, and Bubblewrap versions when testing. External independent review and successful adversarial Linux tests are release gates.

### Codex with your ChatGPT login

Explicitly approve only your file-backed Codex login:

```sh
cargo build --locked
./target/debug/agentvault --project /absolute/path/to/project doctor \
  --agent codex --codex-auth-file "$HOME/.codex/auth.json"
./target/debug/agentvault --project /absolute/path/to/project run \
  --codex-auth-file "$HOME/.codex/auth.json" -- \
  codex --no-daemon --no-alt-screen --sandbox danger-full-access --ask-for-approval on-request
```

The `danger-full-access` option disables Codex's own nested sandbox; AgentVault's
mandatory OS sandbox still applies. Use a project initialized with `agentvault init`
(and `--runtime-root /opt/homebrew` on macOS for a Homebrew Codex installation).
Do not combine `--codex-auth-file` with `--auth-env`.

This imports only ChatGPT tokens/account information into a disposable, private
Codex home. It does not import host settings, sessions, plugins, or the Keychain.
The approved access, ID and refresh tokens **are readable by the agent and its
subprocesses**, which have network access. Never publish the login file.
The source must be an absolute, current-user-owned, single-linked regular file
with private permissions (`chmod 600`); symlinks in the path are refused.
Keychain-only logins are unsupported: use a separate file-backed login with
`codex -c 'cli_auth_credentials_store="file"' login` if needed. Never print the file.

Refreshed credentials are not written back to the host and are discarded at
session cleanup. OAuth refresh-token rotation can invalidate the original login;
you may need to log in again, and should avoid concurrent sessions sharing the
same refresh token. A fresh login does not bypass ChatGPT usage limits.
This follows Codex's documented file-backed authentication mechanism:
https://learn.chatgpt.com/docs/auth. Live ChatGPT inference must still be verified
in your Terminal; synthetic credential tests do not certify account access.

For an already-running local Ollama server with a compatible model installed:

```sh
agentvault run -- codex --oss --local-provider ollama -m YOUR_LOCAL_MODEL \
  --sandbox danger-full-access --ask-for-approval on-request
```

No provider key is required by AgentVault. Codex's own sandbox is disabled in
this example because AgentVault supplies the mandatory outer OS sandbox.
The agent executable still needs an approved runtime installation. Localhost
TCP connections are allowed; run the model server outside the sandbox so its
model files do not need to be exposed. Host Codex settings remain excluded;
pass provider settings through the agent's supported CLI options. A self-hosted
endpoint that requires credentials still needs explicit credential provisioning.
The current `--auth-env` integration supports only the two named provider keys;
it does not yet support arbitrary self-hosted credential variables. Local model
inference must be verified in a real session.

### Test retained changes before approval

Use the session ID printed after the agent exits. Preview runs the edited copy;
it does not update your original project or approve changes:

```sh
agentvault --project /path/to/project preview SESSION_ID -- npm test
agentvault --project /path/to/project preview SESSION_ID --allow-network-listen --port 5173 -- \
  npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
```

Open `http://127.0.0.1:5173` once the app reports that it is listening.
`--allow-network-listen` explicitly approves TCP server sockets on macOS; without
it, preview denies TCP bind/inbound operations. **Seatbelt cannot reliably
restrict inbound listeners to loopback or selected ports.** A server binding
`0.0.0.0`, `::` or another interface can be reachable from your network. The app's
`--host 127.0.0.1` setting is a convention, not an enforced security boundary.
`--port` is repeatable and prints an expected URL only; it is not a firewall rule
and requires `--allow-network-listen` so an old invocation cannot silently opt in.

Linux uses the existing shared host network: neither this flag's absence nor
`--port` restricts listening ports there. Configure your app for loopback.
AgentVault does not automatically open a browser or certify that a server is
ready. The server's own terminal output reports its startup result.

For a simple Python project, run:

```sh
agentvault --project /path/to/project preview SESSION_ID --allow-network-listen --port 8000 -- \
  python3 -m http.server 8000 --bind 127.0.0.1
```

On macOS, use `python3.12` from the approved Homebrew runtime instead of
`python3` if the latter selects Apple’s Xcode launcher. The native test suite
requires the same standalone Python 3.12 runtime.

Stop the foreground server with Ctrl-C. Then review and approve:

```sh
agentvault --project /path/to/project review SESSION_ID --diff
agentvault --project /path/to/project review SESSION_ID --apply
```

Each preview uses the configured OS sandbox and a fresh private home/temp with
no imported agent credentials, host `.env`, SSH agent or host dependency cache.
Commands are resolved from approved runtimes. Existing permitted workspace files
remain visible. Preview can modify code and create build artifacts; all such
changes are rescanned and included in the next review. The original session
baseline remains unchanged. Exit codes are preserved; a failing test never
approves or applies files. Review/apply and another preview of that session are
refused while the preview command is active.

Dependencies and tools must be available inside the sandbox. AgentVault does not
install dependencies automatically. Relative links such as
`node_modules/.bin/acorn -> ../acorn/bin/acorn` are supported when they point
directly to a permitted regular file also copied into the workspace. The copier
reads link text without following it and recreates the link only after copying
its target. Absolute links, outside/secret targets, directory links, link chains,
special files and hard links remain rejected. Size/file-count limits still apply.
Consequently pnpm/workspace directory-link layouts and some builds remain
unsupported.
No exception is made to these checks for preview. An unsafe output remains
unapplied; repair or discard that session before retrying. After an abrupt crash,
stale `sandbox-home`/`sandbox-tmp` siblings can cause a fail-closed startup refusal;
discard that session and start a fresh one rather than reusing unknown state.

### CLI, library, backend and mobile toolchains

`preview` also runs tests, compilers and executable project scripts such as
`./gradlew` and `./mvnw`. Optional `toolchains` entries explicitly approve
read-only Rust/Go/JDK/Android SDK/Xcode roots; caches remain private. Use
`agentvault tools --check` for actual sandboxed executable version checks.
See [toolchain configuration and project examples](docs/toolchains.md).
SDK exposure is implemented; full Android/iOS builds, emulator/Simulator,
USB/device, GUI and release-signing workflows have not been certified or
integrated. These commands never automatically expose host homes or credentials.
