# macOS release checklist

Target: a reliable native macOS core CLI release on an explicitly recorded
macOS version, architecture, agent version, and approved runtime installation.
Passing this checklist is a scoped release decision, not a guarantee against
all security vulnerabilities. Browser review is maintained on its own branch.
Linux and Windows work is outside this release effort.

## Required gates

| Gate | Evidence / current status |
| --- | --- |
| Default tests, formatting, strict Clippy | Passed 2026-11-24 in `macos-20261124T154048Z.log`; 60 library tests passed, 1 ignored, and all default integration suites passed |
| Native filesystem/process security suite | 21 real Seatbelt tests passed in the 2026-11-24 native report |
| Native retained CLI review/apply lifecycle | 4 real workflow tests passed, including successful explicit apply and signal-terminated retention |
| Native preview and configured toolchains | 4 preview tests and 1 toolchain test passed |
| Xcode license, framework and workspace discovery | 1 real test passed on 2026-11-19 with `/Applications/Xcode.app` and an accepted host license; the test did not change license state |
| Provider network | No-key DNS and HTTPS diagnostic passed in the production Seatbelt profile on 2026-11-19; endpoint returned expected HTTP 401. This does not validate authenticated agent login or inference |
| Xcode compiler broker | Passed 2026-11-20 in `macos-ib-bridge-20261120T030619Z.log`: constrained XIB/storyboard/link jobs, asset catalog/symbol jobs, and a synthetic unsigned Simulator-target app build. Shared Simulator services were explicitly enabled for compiler jobs. This validates compilation, not booting a Simulator or running an app |
| Live agent compatibility | One ChatGPT file-backed Codex workflow on a disposable project exited successfully and applied reviewed changes. Exact Codex version and systematic terminal/signal behavior are still unrecorded |
| Installation and documentation | Apple Silicon npm tarball installed into a temporary prefix. Version, initialization, sandboxed shell launch, protected-file exclusion, diff, and apply passed the local smoke test. |
| Recovery and conflicts | Version-2 rollback/conflict tests pass. New simulation covers all 10 journaled operations and 11 interruption cut points; actual power-loss/I/O fault injection and Linux-native execution remain unverified |
| Independent security review | Not completed; cannot be certified by self-tests |

Run from an ordinary Terminal:

```sh
cd /path/to/your/runboundary/checkout
bash scripts/test-macos.sh --runtime-root /opt/homebrew
```

The runner writes a full `.log` and a `.checks.tsv` file under `test-results/`.
It records OS/tool versions and source fingerprints. It runs all core native
suites, including all four native workflow cases. It imports no agent login or
API key and makes no model requests. It exits nonzero when any check group fails.
An omitted optional Xcode check is reported as not run, never as a passing gate.
A passing runner is evidence for its listed suites, not every release gate.

For live agent evidence, use a disposable synthetic project with fake protected
files and a harmless source edit. Record `sw_vers`, `uname -m`, `codex --version`,
the authentication method, terminal input/resize/Ctrl+C behavior, sandbox doctor
result, source edit, review, apply, and source verification. Do not record token
contents or approve real application secrets. The developer's ChatGPT login is
explicitly provided only through `--codex-auth-file`; host configuration is not
imported automatically. Live agent evidence is separate from the shell tests.

## Build the npm package

On an Apple Silicon Mac with Xcode Command Line Tools, native npm, and a stable
Rust toolchain, run:

```sh
rustup target add aarch64-apple-darwin
bash scripts/pack-npm-macos.sh
```

The script writes a tarball in `target/npm/` with the Cargo binary's version.
It contains the native Apple Silicon executable and installs the `runb`
command. npm checks the platform and CPU architecture before installation.

Install the tarball into a temporary prefix and check the installed command:

```sh
prefix=$(mktemp -d)
npm install --global --prefix "$prefix" /path/to/runboundary-VERSION.tgz
"$prefix/bin/runb" --version
```

Run `init`, `doctor sh`, and `run sh` with the installed binary from a
disposable project directory. After the release checks, publish the tested
tarball to npm.

## Experimental Xcode compilation

Opening the retained project in host Xcode is the supported manual development
path; Xcode itself runs outside RunBoundary's sandbox. It must not be advertised
as isolated GUI execution, Simulator launch, device deployment, or signing.

The separate `ios-build`/compiler broker remains experimental. Its completion
requires the native compiler canary, typed IB and asset jobs, complete fixture,
and selected real-app build described in [ios-build.md](ios-build.md). Shared
Simulator-service access must remain explicit. Core CLI passing results must
not be used to claim these compiler gates passed.

## Review and secret handling

Terminal review, the short `diff` and `apply` commands, and heuristic redaction
of credential-like text in terminal diffs are part of the preview. The separate
`webreview` branch contains the experimental browser interface, which renders
permitted source without credential redaction. Keep secrets out of permitted
source because agents can read those files inside the sandbox.
