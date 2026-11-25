# Native macOS backend (experimental)

See the [macOS release checklist](macos-release.md) for current release gates,
including native suite reproduction and evidence still required.

**All 15 native macOS security tests passed** in the supplied report
`macos-20261021T171714Z.log`, on macOS 26.5.1 arm64 with explicitly approved
Homebrew runtimes. The 22 regular tests, formatting and strict Clippy also pass.
The temporary CLI launch block has been removed; startup still requires the
real sandbox probe. Live agent authentication and interactive sessions remain
unverified, and the backend remains experimental.

The process-data disclosure found during development is fixed for the tested
APIs and configuration. The generated policy retains the startup self-information
rule and appends `(deny process-info*)` after all grants. Tests prove that both
KERN_PROCARGS and KERN_PROCARGS2 return EPERM when trying to read another host
process's synthetic arguments and environment, directly and in a spawned child.
Unsandboxed controls and the historical vulnerable profile retrieve both markers.
Sysctl-only denials failed to block these APIs in the same comparison.

Reproduce the full suite:

```sh
bash scripts/test-macos.sh --runtime-root /opt/homebrew
```

For the focused synthetic comparison:

```sh
bash scripts/diagnose-macos-process.sh --runtime-root /opt/homebrew
```

The comparison writes `test-results/macos-process-<timestamp>.log`. It prints
only return codes and synthetic marker-presence booleans, never process contents.
It never launches coding agents or imports approved authentication. A payload
that cannot start is a failed check, never a successful denial.

RunBoundary now implements a native `seatbelt` backend through Apple's
`/usr/bin/sandbox-exec`. A Linux VM is not needed to run this backend. Linux
continues to use Bubblewrap. There is no fallback between the two backends.

The managed assistant session still rejects nested sandbox startup with
`sandbox_apply: Operation not permitted`. The passing native report was run
by the developer from Terminal and inspected by the assistant. Its results
apply to the tested configuration and covered behaviors, not every macOS
version or attack path. Live Codex/Claude sessions require separate validation.

## Run the native checks

You already have Homebrew Node.js and Python 3.12 in /opt/homebrew on the
initial development Mac. From Terminal:

```sh
cd /path/to/your/runboundary/checkout
bash scripts/test-macos.sh --runtime-root /opt/homebrew
```

No Multipass or Linux configuration is involved. This script uses Cargo from
your PATH, or the temporary /private/tmp development toolchain if still
present. If neither exists, install a Rust stable toolchain first. It checks
formatting, ordinary tests, Clippy, and the explicitly selected native macOS
OS tests. Reports are saved to `test-results/macos-*.log`. It does not import
API keys or run a paid model request. Tests use synthetic secrets.

The default Cargo test invocation ignores the OS-specific suites. The native
runner explicitly selects `macos_test`, leaving Linux-only tests unselected.
Fourteen macOS tests exercise direct/Python/Node reads, source/template edits,
private directories, host credentials and writes, a host Unix socket,
descendants/symlinks and attempted re-sandboxing, inherited descriptors,
standard-stream restrictions, exit status, invalid-profile failure, protected
sync output, another host process's environment, and outbound IP connections.
Python tests require a real approved `python3.12` executable; Node tests require
an approved `node` executable. Missing runtimes are explicit prerequisite
failures, not silent passes.

`--runtime-root /opt/homebrew` is explicit approval to read that runtime tree.
It may contain more than your agent binary; do not approve a tree containing
secrets or unrelated projects. No host home directory is approved. On an Intel
Mac with a reviewed Homebrew installation use `/usr/local` instead. Runtime
ownership/permission checks still apply; the script does not chmod your tools.
Approving a runtime also trusts its owner and macOS admin-group writers, as
standard Homebrew directories may be group-writable by administrators. Other
group-writable, world-writable, and setuid/setgid paths are rejected.

## Try a disposable shell session

With [`runb` installed](../README.md#usage), try a project with synthetic secrets:

```sh
mkdir -p /private/tmp/runboundary-mac-demo
cd /private/tmp/runboundary-mac-demo
printf 'FAKE_SECRET=example-only\n' > .env
printf 'EXAMPLE=value\n' > .env.example
printf 'original\n' > source.txt

runb init
runb doctor sh
runb run sh
```

Inside that shell:

```sh
pwd
cat .env
cat .env.example
cat /private/tmp/runboundary-mac-demo/.env
printf 'edited\n' > source.txt
exit
```

The sandbox's current directory is the real temporary workspace path; macOS
has no `/workspace` mount alias. The copied `.env` is absent and the original
`.env` must be denied. The template and source edit must work. The original
source remains unchanged until you explicitly approve synchronization:

```sh
runb diff SESSION
runb apply SESSION
```

Replace SESSION with the printed identifier. `init` refuses to overwrite an
existing configuration. For a previous Linux configuration, explicitly change
`sandbox.backend` to `seatbelt`; keep your existing protection rules.

## Codex and Claude

RunBoundary sets `CODEX_CA_CERTIFICATE` and `SSL_CERT_FILE` to the existing
public `/private/etc/ssl/cert.pem` bundle on macOS. Codex documents these for
HTTPS/login/WebSocket trust configuration. The file must be root-controlled,
regular, single-link and nonempty; it is already read-only in the sandbox.
Certificate and hostname verification remain enabled. No private key,
personal Keychain, arbitrary host CA override, or TLS-verification bypass is
imported. Corporate TLS interception requiring an additional private CA is
not automatically supported. See the [official variable reference](https://learn.chatgpt.com/docs/config-file/environment-variables).

If the DNS/HTTPS diagnostic passes but Codex still reconnects, use the explicit
live diagnostic from your Terminal with `OPENAI_API_KEY` already set:

```sh
bash scripts/diagnose-live-codex.sh --runtime-root /opt/homebrew
```

Unlike the public network probes, this makes real authenticated model requests
and API charges may apply. It creates a fresh synthetic project, builds the
current CLI without exposing the key to build scripts, and launches Codex only
through RunBoundary. Each attempt has provider retries disabled and a 60-second
deadline (plus shutdown time). It uses a custom `runboundary-diagnostic`
provider pointed at the official `https://api.openai.com/v1` API and reads the
approved key by environment-variable name. Built-in provider IDs such as
`openai` are never overridden. It requests a short reply without tools, first
with WebSockets requested and then, only on failure, with HTTP/SSE requested
via `model_providers.runboundary-diagnostic.supports_websockets=false`.
These are requested transports, not a claim that a successful reply has
verified which wire protocol the client selected. No sandbox permissions change.
Output is bounded, credential-redacted and control-escaped before writing a
private `test-results/codex-live-<timestamp>.log`. Oversized or incomplete
captures are withheld. A successful exit plus an actual completed JSON agent
reply is required; an echoed prompt does not count. This verifies a model
reply only, not interactive editing or synchronization. Provider quota errors
stop the diagnostic immediately: resolve API credits/project or organization
usage limits before retrying; a second transport cannot fix unavailable quota.
API-key billing is separate from ChatGPT subscription usage. The six offline
harness tests can be run without credentials or internet:

```sh
python3 -m unittest discover -s scripts/tests -p test_live_codex_diagnostic.py -v
```

For a fresh project using explicitly approved Homebrew tools:

```sh
runb init --runtime-root /opt/homebrew
runb doctor codex --auth-env OPENAI_API_KEY
runb run --auth-env OPENAI_API_KEY codex
# Or:
runb run --auth-env ANTHROPIC_API_KEY claude
```

Provider credentials are optional. Local or self-hosted models can run without
credential flags; the agent handles provider authentication when needed.
For the explicit API-key commands above, set your provider credential securely
in your own Terminal environment first. Never put it in YAML or command-line
arguments. Codex's API-key login runs only when `OPENAI_API_KEY` is explicitly
approved, inside the private session home. Host ~/.codex, ~/.claude, Keychain, SSH agent,
and OAuth caches are not imported automatically. To explicitly use a file-backed ChatGPT login, choose `--codex-auth-file "$HOME/.codex/auth.json"` instead of `--auth-env`; see the README for the full workflow and refresh-token limitations. Home-installed agent binaries are not
supported by approving your entire home. These commands describe the intended
integration; live login, terminal behavior, and agent-version compatibility
still need validation.

The private macOS home and temporary directory are filesystem directories
inside the 0700 session parent, not tmpfs mounts. RunBoundary removes those two
directories after the main process returns and before retaining source edits.
Approved credentials can still be deliberately copied by an agent into
permitted source files; the filesystem sandbox cannot prevent that.

## Boundary and limitations

If an agent opens but cannot connect to its provider, run the separate public
DNS/HTTPS diagnostic from Terminal:

```sh
bash scripts/diagnose-macos-network.sh --runtime-root /opt/homebrew
```

It sends unauthenticated requests to `https://api.openai.com/v1/models` using
Node and system curl, and separately tests DNS. HTTP 401 confirms HTTP/TLS
connectivity, not valid credentials or successful inference. It compares the
same clean environment outside the sandbox, the exact production profile,
and narrowly scoped macOS DNS, network-control and TLS-service candidates.
It imports no API keys, proxy values or user curl configuration, prints no
response bodies, and leaves the production policy unchanged. Proxy/CA variable
presence is reported without values, to identify unsupported managed-network
requirements. A failed host baseline is not evidence of a sandbox bug.
It also checks named resolver aliases and OpenSSL configuration-file access
without printing contents, and attempts read-only macOS denial-log collection
restricted to its own unauthenticated probe process IDs. Log availability is
not guaranteed; the tests do not claim complete denied-operation visibility.
The report is `test-results/macos-network-<timestamp>.log`. This internet
diagnostic is separate from the deterministic native OS suite. The local TCP
test alone does not certify DNS, TLS, provider connectivity or streaming.

The profile starts with `(deny default)`. It grants read/write access only to
the copied workspace, private home, and private temporary directory. System
runtime trees and selected system configuration files are read-only; additional
tool trees require explicit approval. The root-controlled
`/private/var/select/sh` shell selector receives a literal read allowance and
ancestor metadata access, with its target required to be a trusted system
runtime. Its parent tree is not broadly readable. Original-project overlap with runtime
trees is refused. Parent directories get only narrowly named metadata access,
not directory-listing or file-content access. The literal root directory `/`
is readable so Apple's dynamic loader can open it as an `openat` base; this
exposes top-level entry names, without granting access to their contents.
The broad `/System` tree is not
readable: `/System/Volumes/Data` contains aliases to host user data.

Codex's named system policy paths under `/etc/codex` (and canonical
`/private/etc/codex`) get literal read probes, with metadata-only ancestor
access, so absent optional policy returns ENOENT rather than sandbox EPERM.
An existing `requirements.toml` must be root-controlled, regular and single-link;
it is agent-readable and must not contain credentials. Existing `config.toml`
or legacy `managed_config.toml` defaults are refused because they may contain
credentials; automatic import of those files is unsupported. The policy
directory cannot be a symlink. There is no subtree read allowance or write
permission for `/etc/codex`, and host user configuration remains excluded.

Paths are SBPL parameters passed separately with `-D`, never interpolated into
policy source. Symlinks resolve under the kernel policy, while preparation and
synchronization also retain their no-follow checks. Descendants inherit the
sandbox. Standard streams must be terminals/pipes or /dev/null; the child lists
its actual descriptor table after fork and marks descriptors above stderr
close-on-exec. An overfull/failed descriptor listing refuses launch. A new
terminal session limits controlling-terminal input injection. Interactive
compatibility still requires an actual terminal session test.

Only named DNS/configuration/notification Mach services are allowed. No
unrestricted Mach lookup, Keychain broker, Apple Events, or launchd service
access is approved. sysctl reads cover named hardware/OS discovery, not
kern.procargs and other process environments. Outbound IP networking is
allowed, including localhost. The exact macOS DNS daemon socket
`/private/var/run/mDNSResponder` is an intentional outbound exception; other
host Unix sockets remain denied, including SSH-agent and Docker sockets.
The exception enables DNS requests to an OS service and is not a directory
read/write grant. IP networking
is not data-loss prevention and can reach host services over TCP.

This is path-based kernel mediation, **not Linux namespace isolation**: no
private PID namespace, mount namespace, Linux capabilities, or Linux
no_new_privs claim is made for macOS. The filesystem layout remains the host
layout with denied accesses. Process information, GUI APIs, brokers, compiler
and certificate access may need additional narrowly reviewed compatibility
work; there is no automatic permission widening. No resource quotas or
complete process-tree lifecycle guarantee exists. The supervisor signals the
session process group, but a descendant that creates another session may
outlive it while retaining the filesystem restrictions. Do not equate the two
backends' security properties.

Apple marks sandbox-exec deprecated and its system SBPL profiles describe the
interface as private and changeable. RunBoundary therefore probes real startup
and exclusion behavior each time, refuses unavailable controls, and treats
this backend as experimental. Future macOS releases may require changes.
Local primary references: `man sandbox-exec`, and Apple's installed
`/System/Library/Sandbox/Profiles` for operation/filter definitions. No broad
Apple system profile is imported, because those profiles grant unrelated
broker and filesystem permissions.

## Preview the app before applying its edits

With the session ID printed when Codex exits:

```sh
runb preview SESSION_ID --allow-network-listen \
  python3.12 -m http.server 8000 --bind 127.0.0.1
```

Use the approved Homebrew `python3.12` runtime; Apple’s `/usr/bin/python3` is
an Xcode launcher whose developer-tool discovery is intentionally unavailable
inside the sandbox.

Open http://127.0.0.1:8000 after Python reports that the server started. This
serves the retained edited copy. Stop it with Ctrl-C, then use
`runb diff SESSION_ID` and `runb apply SESSION_ID` from the same project.
For Vite, use `--allow-network-listen npm run dev -- --host 127.0.0.1 --port 5173 --strictPort`.
See the README for dependency/symlink limitations, generated build output, and
fresh-home/no-credential behavior. The macOS test runner also runs the opt-in
`preview_test` suite, including an actual localhost HTTP round trip with
synthetic data and no API key.

TCP listener access now requires `--allow-network-listen`. Without it, macOS
previews deny TCP binds. With it, listener address/port confinement is not
enforced: `--port` is an expected URL, not a firewall. Bind the app to
`127.0.0.1`; other interfaces can expose it to the LAN. This is an application
setting rather than an OS guarantee. The native preview suite checks default
TCP bind denial separately from an explicitly opted-in HTTP preview.
