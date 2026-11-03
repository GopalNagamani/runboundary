# Configuration reference

The complete default configuration is [examples/agentvault.yaml](../examples/agentvault.yaml). Only agentvault.yaml in the selected project is loaded. Unknown fields, oversized configuration files (>128 KiB), YAML errors, symlinked/multiply-linked configurations, and unsupported versions are rejected.

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

1. Always exclude .git, .aws, .ssh, .kube, .codex, .claude directory/path components, agentvault.yaml components, and every component starting with .agentvault. Unsafe relative paths also refuse access.
2. The built-in sensitive globs remain mandatory even if removed from YAML.
3. The two named template exceptions may override the default .env.* rule, if listed in allowed. An additional custom protection such as **/.env.example or **/*.example wins over that exception. A template inside an always-excluded directory remains excluded.
4. Every other protected match wins. Otherwise copy the regular file, subject to no-follow and link/metadata validation.

This narrow allow feature deliberately cannot express broad wildcard exemptions. A custom ** protection may exclude every path, including templates. No content inspection is performed to decide whether an apparently safe source file contains a secret.

On Linux, PATH is always replaced with /usr/local/bin:/usr/bin:/bin for runtime resolution, even if absent from environment.allow; HOME is /home/agent and TMPDIR is /tmp. The host PATH is never inherited. Terminal/locale variables are copied only when approved and bounded/control-free. Runtime hooks such as LD_PRELOAD, NODE_OPTIONS, PYTHONPATH, proxy variables, SSH_AUTH_SOCK, and arbitrary credentials are not inherited. Agents may still read approved runtime configuration inside the exposed system mounts.

Authentication is separate from YAML: `--auth-env OPENAI_API_KEY` and `--auth-env ANTHROPIC_API_KEY` approve named existing environment variables. Values are supplied through execve environment, not command-line arguments. `--codex-auth-file /absolute/path/auth.json` instead approves a file-backed ChatGPT login for Codex, mutually exclusive with --auth-env. Only validated ChatGPT credential fields are copied to the disposable private home, never a whole host OAuth directory or Keychain. Refreshed credentials are discarded, not written back; token rotation may require re-login. `doctor` validates the selected local credential source but does not contact the provider or validate token scope. See the README for commands and credential exposure limitations.

## Platform-specific initialization

Provider authentication is optional. AgentVault does not require keys based on
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
[examples/agentvault.macos.yaml](../examples/agentvault.macos.yaml).
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
