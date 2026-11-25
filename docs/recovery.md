# Synchronization recovery

Application is journaled per file; it is not a filesystem transaction. A project-level advisory lock prevents overlapping apply/recovery transactions. Stop project editors and build tools before applying. No process-crash or power-loss atomicity is promised. Recovery directories are excluded from future sandbox copies.

After success, `.runboundary-recovery-*/originals/` contains the original versions of modified/deleted files. Version-2 `journal.jsonl` records each path's expected original and applied content, plus a completion marker. Added paths have no original version. `staged/` holds any not-yet-installed output. Empty directories created during a failed attempt may remain. Ordinary synchronous failures attempt reverse-order rollback and report rollback errors and the exact recovery path.

If an application fails or RunBoundary crashes:

1. Stop edits and preserve the reported recovery directory and retained workspace. Make an independent backup of the current project. Do not blindly rerun apply.
2. From the project root, run `runb recover .runboundary-recovery-ID` with the directory name printed by RunBoundary.
3. Automatic recovery accepts only version-2 journals and only removes current files that still match the journaled applied content. It checks every path before changing any project file. If a path has newer or unexpected content, recovery refuses the transaction; preserve those edits and use the manual procedure below.
4. Run tests and inspect your ordinary source diff. Keep recovery directories and temporary workspaces until satisfied.

Older recovery directories whose journal has no version-2 content hashes cannot be safely recovered automatically. For those, inspect the journal, current paths, `originals/`, and `staged/` manually. An intent record can exist without its operation having occurred. Restore an original only after saving any newer edits; remove an addition only after confirming it is still the session's output.

Filesystem permission or I/O failures can still interrupt recovery; the journal is left available for another attempt or manual inspection. Do not publish recovery directories: permitted source files may themselves contain credentials.
