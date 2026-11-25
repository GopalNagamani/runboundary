# File-backed agent adapters

## One-time setup

For Freebuff, first install it and log in normally, then run:

```sh
runb auth setup freebuff
```

To approve several built-in profiles together, name them in one command:

```sh
runb auth setup freebuff hermes
```

Setup validates all requested profiles, shows each source/destination mapping,
and asks once to save all approvals. Only an explicit yes saves them; declining
saves none. A missing or already-approved profile also stops the batch before
any changes are made. Setup checks file metadata without reading login contents
before approval. It saves only paths, file types, and color hints in private
user-level files under `~/.config/runboundary/auth/`. Approval applies across
projects; credentials stay in their original files until each approved run.

Afterward, from an initialized project:

```sh
runb doctor freebuff
runb run freebuff
```

Freebuff and Hermes have built-in profiles. Hermes has a Nous-only
authentication profile with a separate runtime limitation (see below). Other
file-backed agents can save a custom manifest through the same approval flow,
one agent per command:

```sh
runb auth setup your-agent --adapter /absolute/path/adapter.json
```

Explicit `--auth-adapter`, `--codex-auth-file`, or `--auth-env` options override
saved selection. An invalid saved profile fails closed rather than silently
falling back. To bypass saved approval for one invocation, pass `--no-saved-auth`
to run or doctor. To revoke it:

```sh
runb auth remove freebuff
```

Removal deletes only saved approval. It does not log out, delete host login
files, or remove cached programs. To change a saved profile, remove it and run
setup again. Setup requires no initialized project and never overwrites an
existing approval. Direct custom manifests and the Python Freebuff generator
below remain supported for advanced use.


`--auth-adapter /absolute/path/adapter.json` works with any trusted agent CLI
whose login can be supplied as named files under its home directory. It is an
explicit alternative to `--codex-auth-file` and `--auth-env`, not a way to import
an entire home, Keychain, credential directory, or host agent configuration.
Existing Codex support remains unchanged and filters its known credential schema.

Example manifest (replace every source with a real absolute path):

```json
{
  "version": 1,
  "agent": "your-agent",
  "files": [
    {
      "source": "/absolute/host/path/login.json",
      "destination": ".config/your-agent/login.json",
      "kind": "credential"
    }
  ]
}
```

Keep the manifest outside the project, current-user-owned, single-linked and
private (`chmod 600`). Sources must be absolute paths without symlinks or hard
links. Destinations are relative to the disposable HOME without parent traversal.
`agent` must match the launched executable basename; shell wrappers do not match.
File contents are copied exactly, so approve only minimal dedicated login files.
Generic adapters cannot filter unknown credential schemas. Configuration and
history should not be listed unless deliberately approved.

```sh
runb doctor your-agent --auth-adapter /absolute/path/adapter.json
runb run --auth-adapter /absolute/path/adapter.json your-agent
```

Each `files` item has a `kind`: `credential` (default, at most 256 KiB), `cache`
(at most 256 KiB), or `executable` (at most 128 MiB). At most 32 files and 160 MiB
total can be imported. Credentials must be current-user-owned and private (600).
Cache/executable sources may be readable by others but cannot be writable by
others. Imported credentials/caches have mode 600; executables have mode 700.
Executable entries explicitly approve code to run inside the sandbox. Imported
files are not synchronized to your source project.

Only optional `terminal` keys `COLORTERM` and `COLORFGBG` can override display
hints. They cannot change HOME, PATH, loaders, proxies, or provider credentials.

## Freebuff

Freebuff's installed npm launcher uses `.config/manicode` under HOME for its
cached binary and state. The helper below generates an explicit manifest from
existing host files, inspecting filenames and metadata without reading secrets:

```sh
python3 scripts/create-freebuff-adapter.py --output "$HOME/freebuff-adapter.json"
```

Run this once from the RunBoundary repository after installing Freebuff and
logging in normally. Existing output files are never overwritten. It lists the
observed `credentials.json`, `device-key.json`, cached `freebuff` binary, and
available metadata/rg/tree-sitter artifacts. It excludes settings, message history,
and analytics IDs. These names match the installed launcher/state observed during
development; future Freebuff versions may change them. This profile still needs
live validation in the developer's Terminal.

From your project:

```sh
runb doctor freebuff --auth-adapter "$HOME/freebuff-adapter.json"
runb run --auth-adapter "$HOME/freebuff-adapter.json" freebuff
```

The profile supplies dark-background hints, so no shell wrapper is needed.
The cached executable and download metadata avoid the empty-home cache miss;
Freebuff can still perform its own update checks. Recreate the manifest if the
required file list changes. Host updates to named source files are imported on
subsequent runs; the manifest does not contain their secret contents.

## Hermes / Nous Portal

```sh
runb auth setup hermes
```

This profile is based on the inspected Hermes v0.22.7 authentication code. Setup
lists `.hermes/auth.json` and `.hermes/config.yaml`, checks their metadata, and
asks before saving paths. Credentials are not read until an approved import.
The source auth store must be private and version 1, with `providers.nous`.
Account OAuth and anonymous/guest Nous identity fields are supported. Other
providers, credential pools, arbitrary fields, and TLS overrides are excluded.
Only `model.default` (or `model.model`) and a forced `provider: nous` survive
configuration import. Hooks, MCP servers, shell commands, environment, API keys,
history, memories, skills, and host `.env` files are not copied. Choose Nous
Portal in Hermes first; an explicitly different provider fails import.

The profile stores paths only; imported auth/config files are 600 in the private
home. It does not import the cross-profile shared credential store or write
refreshed credentials back to the host. Rotation can require a new host login.
Revoke with `runb auth remove hermes`.

### Dedicated Hermes runtime on macOS

The inspected `~/.local/bin/hermes` launcher references home-installed Python
and code, which remain outside the approved runtime policy. An adapter alone
cannot authorize those directories. Prepare a separate runtime instead:

```sh
brew install python@3.14
cd /path/to/your/runboundary/checkout
/opt/homebrew/bin/python3.14 scripts/install-hermes-runtime.py --plan
/opt/homebrew/bin/python3.14 scripts/install-hermes-runtime.py
```

The installer creates `/opt/homebrew/opt/runboundary-hermes` and an exclusive
`/opt/homebrew/bin/hermes` symlink. It exports the installed checkout's committed
HEAD (uncommitted changes are not included), omits credential-like archive paths,
rejects unsafe archive entries, and installs dependencies into its own venv.
Hermes explicitly blocks ordinary wheel builds in the inspected version, so it
uses the supported editable install against this dedicated snapshot. There is
no editable link to your home checkout. Build subprocesses receive a temporary
HOME and a filtered environment without host credentials or pip configuration.
Installation runs normal trusted package build code on the host and downloads
Python dependencies; it is not an RunBoundary-sandboxed build.

Existing runtime/launcher paths are never overwritten. The original Hermes
installation and Nous login remain untouched. On Intel Homebrew, use
`--homebrew-root /usr/local` and the corresponding Python path. The project's
`sandbox.runtime_roots` must explicitly include the chosen Homebrew root; no
project policy is modified automatically.

Then, from your initialized project with saved Hermes approval:

```sh
runb doctor hermes
runb run hermes
```

This installer has planning/archive tests but has not yet completed a real
runtime installation or live sandbox launch. Runtime or Hermes dependency
compatibility errors must be investigated without widening home access.

Synthetic filtering/setup tests pass; live Nous Portal authentication is not
certified. No model requests or host credential reads were performed during
adapter development.

## Limits and credential lifecycle

Credentials are readable by the agent and its descendants and may be transmitted
by them. Private copies are deleted at session cleanup, as with Codex login.
Refreshed credentials are never automatically exported to the host. Providers
that rotate tokens may require re-login; concurrent sessions sharing refresh
credentials can interfere. Keychain-only login, external credential brokers,
custom credential environment variables, and host-bound device identity may need
a provider-specific integration. This is a universal file-mapping mechanism,
not a certification that every agent's authentication protocol works.

Doctor validates local import and sandbox startup, not provider authentication.
Use synthetic projects to test each agent/version and complete edit/review/apply.
