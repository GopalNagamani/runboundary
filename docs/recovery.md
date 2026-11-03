# Synchronization recovery

Application is journaled per file; it is not a filesystem transaction. Stop project editors and build tools before applying. No process-crash or power-loss atomicity is promised. Recovery directories are excluded from future sandbox copies.

After success, `.agentvault-recovery-*/originals/` contains the original versions of modified/deleted regular files. `journal.jsonl` records intended operations, original-existence flags, and a completion marker after successful application. Added paths have no original version. `staged/` holds any not-yet-installed output. Empty directories created during a failed attempt may remain. Ordinary synchronous failures attempt reverse-order rollback and report rollback errors and the exact recovery path.

If an application fails or AgentVault crashes:

1. Stop edits and preserve the reported recovery directory and retained workspace. Make an independent backup of the current project. Do not blindly rerun apply.
2. Inspect the journal, the current paths, `originals/`, and `staged/`. An intent record can exist without its operation having occurred; it is not a completion record.
3. For each changed/deleted original that actually exists under `originals/`, compare it with the current project file. Restore that original only after saving any newer edits. For additions, remove only files verified to be the session's additions, saving later edits first.
4. If rollback reported errors, inspect those paths individually. Protected files are never legitimate synchronization targets; investigate any such path in a journal.
5. Run tests and inspect your ordinary source diff. Delete recovery directories and temporary workspaces only when satisfied.

No automatic crash-recovery command is provided. Filesystem permission or I/O failures can prevent automatic restoration; recovery originals and the journal must be retained for developer inspection. Do not publish them: permitted source files may themselves contain credentials.
