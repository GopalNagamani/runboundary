# RunBoundary for macOS

RunBoundary runs coding agents in a native Seatbelt sandbox with a copied,
filtered project workspace. This npm distribution includes the `runb`
executable for Apple Silicon Macs. The native macOS backend is experimental.
Linux and Windows npm releases are coming soon.
The workspace limit is 1 GiB total and 64 MiB per file.

The preview includes terminal review through `runb diff SESSION` and explicit
approval through `runb apply SESSION`. Browser review is in development.
Protected files are excluded from the agent's workspace, and terminal diffs
redact common credential patterns in displayed text.

From your project directory, run:

```sh
runb init
runb doctor sh
runb run sh
```

## Connect an agent

Install the agent in an approved runtime first. For a Homebrew install, add
`/opt/homebrew` to `sandbox.runtime_roots` in `runboundary.yaml`, or initialize
a new project with `runb init --runtime-root /opt/homebrew`.

- Codex with a file-backed ChatGPT login uses `runb run --chatgpt codex`.
- Codex with an API key uses `runb run --auth-env OPENAI_API_KEY codex`.
- Claude Code with an API key uses `runb run --auth-env ANTHROPIC_API_KEY claude`.
- Freebuff and Hermes use `runb auth setup AGENT` once, then `runb run AGENT`.

For prerequisites, sign-in steps, and custom adapters, see [Connect an agent](https://github.com/GopalNagamani/agentvault/blob/develop/README.md#connect-an-agent).

## Edit the project policy

`runb init` creates `runboundary.yaml` in the project root. Open it in your editor
and append paths or globs to `filesystem.protected` to keep them out of the
agent's workspace. For example, add `- "private"` to that list to exclude a
top-level `private` directory. Run `runb doctor sh` after saving to check
the policy and sandbox startup. See the [configuration reference](https://github.com/GopalNagamani/agentvault/blob/develop/docs/configuration.md)
for supported fields and matching rules.

See the [macOS guide](https://github.com/GopalNagamani/agentvault/blob/develop/docs/macos.md)
for runtime setup, agent usage, and sandbox limitations.
