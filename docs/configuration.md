# Configuration reference

RunBoundary loads `runboundary.yaml` from the selected project and stores project
state in `.runboundary/`. See the [default policy](../examples/runboundary.yaml).
RunBoundary rejects unknown fields, files over 128 KiB, invalid YAML, symlinked
or multiply linked configurations, and unsupported versions.

If you used a development build before the rename, stop any active sessions and
rename `agentvault.yaml` to `runboundary.yaml` to retain your policy. If the new
destination is absent, rename `.agentvault/` to `.runboundary/` to retain audit
logs and pending reviews. Keep retained workspaces and recovery directories in
place. Saved login adapter approvals can be moved from `~/.config/agentvault/`
to `~/.config/runboundary/` if the new directory is absent, or set up again with
`runb auth setup`.

| Field | Accepted behavior |
| --- | --- |
| version | Exactly 1 |
| sandbox.enabled | Must be true |
| sandbox.backend | bubblewrap on Linux; seatbelt on macOS; mismatches refuse launch |
| sandbox.runtime_roots | Optional explicit read-only macOS tool trees under /opt or /usr/local; default empty; unsupported for Bubblewrap |
| sandbox.fail_closed | Must be true |
| filesystem.protected | Additional relative glob patterns; mandatory default patterns cannot be removed by editing this list |
| filesystem.allowed | Only **/.env.example and **/.env.sample; other patterns refuse validation |
| environment.inherit_all | Must be false |
| environment.allow | Any subset of PATH, TERM, LANG, LC_ALL |
| audit.enabled | Must be true |
| audit.redact_secrets | Must be true; does not redact arbitrary live agent output |

Patterns use globset relative-path semantics; `**/` covers any nesting level including the project root. Absolute patterns and `..` components are rejected. A protected directory is pruned, so its descendants are never copied.

Precedence is deterministic:

1. Always exclude .git, .aws, .ssh, .kube, .codex, .claude directory/path components, runboundary.yaml components, and every component starting with .runboundary. Unsafe relative paths also refuse access.
2. The built-in sensitive globs remain mandatory even if removed from YAML.
3. The two named template exceptions may override the default .env.* rule, if listed in allowed. An additional custom protection such as **/.env.example or **/*.example wins over that exception. A template inside an always-excluded directory remains excluded.
4. Every other protected match wins. Otherwise copy the regular file, subject to no-follow and link/metadata validation.

This narrow allow feature deliberately cannot express broad wildcard exemptions. A custom ** protection may exclude every path, including templates. No content inspection is performed to decide whether an apparently safe source file contains a secret.

On Linux, PATH is always replaced with /usr/local/bin:/usr/bin:/bin for runtime resolution, even if absent from environment.allow; HOME is /home/agent and TMPDIR is /tmp. The host PATH is never inherited. Terminal/locale variables are copied only when approved and bounded/control-free. Runtime hooks such as LD_PRELOAD, NODE_OPTIONS, PYTHONPATH, proxy variables, SSH_AUTH_SOCK, and arbitrary credentials are not inherited. Agents may still read approved runtime configuration inside the exposed system mounts.

Authentication is separate from YAML: `--auth-env OPENAI_API_KEY` and `--auth-env ANTHROPIC_API_KEY` approve named existing environment variables. Values are supplied through execve environment, not command-line arguments. `--codex-auth-file /absolute/path/auth.json` instead approves a file-backed ChatGPT login for Codex, mutually exclusive with --auth-env. Only validated ChatGPT credential fields are copied to the disposable private home, never a whole host OAuth directory or Keychain. Refreshed credentials are discarded, not written back; token rotation may require re-login. `doctor` validates the selected local credential source but does not contact the provider or validate token scope. See the README for commands and credential exposure limitations.

## Workspace size and disk space

RunBoundary estimates the disk space needed for the files it will copy and
checks available space on the temporary workspace volume before copying.
Projects can exceed 1 GiB when there is enough space. Set `TMPDIR` to a private,
writable directory on a larger volume if needed. Space can change during a
run, and retained sessions continue to use space until cleaned up.

The 64 MiB per-file limit applies during copying and review. Use
`filesystem.protected` to omit generated files or caches if needed. RunBoundary
also rejects protected output paths during review and apply.

## Platform-specific initialization

Provider authentication is optional. RunBoundary does not require keys based on
the agent executable's name. Without credential flags, the agent decides
whether its provider needs authentication; host credentials remain excluded.
Codex API-key login is performed only with explicit `--auth-env OPENAI_API_KEY`.
Local model settings can be passed through the agent's supported CLI options.

On macOS, `SSL_CERT_FILE` and `CODEX_CA_CERTIFICATE` are set deterministically
to `/private/etc/ssl/cert.pem`, a public OS CA bundle already allowed read-only.
They are not copied from the host environment. The bundle and its ancestors
must be root-controlled; it must be a nonempty regular single-link file.
Missing or unsafe bundles refuse environment preparation, without disabling
TLS verification. This does not import host user Keychains, private client
keys, or custom corporate CA files. Public CA certificates are an explicit
runtime exception; project PEM files remain protected and excluded.

`init` selects the current host backend. macOS examples are in
[examples/runboundary.macos.yaml](../examples/runboundary.macos.yaml).
`init --runtime-root /opt/homebrew` explicitly approves that entire read-only
runtime tree on macOS. It never overwrites an existing policy or auto-converts
a Linux configuration. The macOS PATH contains approved runtime bins followed
by /usr/bin:/bin:/usr/sbin:/sbin; HOME and TMPDIR point to separate private
session directories rather than Linux /home/agent and /tmp. See
[macOS boundary and limitations](macos.md).

## Optional toolchains

The top-level `toolchains` mapping accepts only `rust.toolchain_root`, `go.root`,
`java.home`, `android.sdk_root`, and `ios.xcode_app`. Every path is a literal
absolute directory approved read-only; iOS is macOS-only and Android also
requires Java approval. These are independent of macOS installation
`runtime_roots` and work with Bubblewrap on Linux too. Omitted entries expose
nothing extra. SDK contents are not filtered by project protected patterns.
See [toolchains](toolchains.md) for prerequisites, cache paths, command examples,
network/service limitations, credential exclusions and verification status.
