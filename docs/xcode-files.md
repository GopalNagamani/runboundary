# Files in Xcode's navigator

AgentVault creates and edits real files in the retained workspace. Classic Xcode
projects also keep a list of navigator references in
`YourApp.xcodeproj/project.pbxproj`. Creating a file on disk does not add that
reference. Editing an existing referenced file needs no registration.

Close the retained project in Xcode before registration so Xcode cannot save
an older project file over the changes. Stop any preview for this session.

Register one file, using the AgentVault session ID printed after the agent exits
(not the Codex conversation ID):

```sh
agentvault --project "/path/to/original/project" xcode-register SESSION \
  --xcode-project YourApp.xcodeproj -- sandbox-check.txt
```

Register several named files by listing them after `--`. Alternatively, discover
all files added since the session started:

```sh
agentvault --project "/path/to/original/project" xcode-register SESSION \
  --xcode-project YourApp.xcodeproj --new-files
```

All paths are relative to the retained workspace, not to your terminal's current
directory. Choose the app's `.xcodeproj`, not its `.xcworkspace` or Pods project.
For `--new-files`, check the session summary first: it includes every new regular
file, including generated files. Use named files when you only want a subset.
Files must lie under the selected `.xcodeproj` directory's parent. Missing files,
symlinks, hard links, protected paths and project bundle internals are refused.
One invalid file rejects the batch before editing metadata.

Reopen the **retained** `.xcworkspace` or `.xcodeproj` in Xcode. Registered files
appear directly under the main navigator group. The original project still has
neither the new file nor its reference until you approve the session:

```sh
agentvault --project "/path/to/original/project" review SESSION --diff
agentvault --project "/path/to/original/project" review SESSION --apply
```

Registration changes the retained project file only. It preserves existing text
and comments with bounded OpenStep parsing and insertion-only edits. Existing
references are detected through relative groups, localization variant groups,
version groups and SOURCE_ROOT references; repeating registration is a no-op.
No Ruby, project hooks, Xcode, build scripts or Simulator services run. The command
uses the per-session lock, safe copier, conflict checks and recovery journal.
Metadata backup originals are retained beside the workspace in its private
session directory. If synchronization fails, follow the printed recovery path
and [recovery instructions](recovery.md) before retrying. Multi-file application
of the session still uses the normal journaled, non-atomic approval workflow.

This command adds **navigator references only**. For a new Swift source file or
resource, choose the intended target membership in Xcode's File inspector when
needed. A text note should not automatically be bundled into your application.
Changes Xcode makes to the retained project metadata are also reviewable session
changes. Folder-synchronized Xcode groups already support file discovery; this
first implementation refuses such projects and unfamiliar group types instead
of rewriting their semantics. Uncommon OpenStep string escapes and nonempty
`projectDirPath` settings are also refused. No protection policy is relaxed.

Opening Xcode normally runs it outside AgentVault's sandbox. Running build
scripts or apps from it uses your host account's permissions. File registration
does not enable protected Simulator integration or certify a complete iOS build.

Run metadata and CLI tests with:

```sh
cargo test --locked --test xcode_register_test
```

On macOS this also checks that Apple's `plutil` accepts the edited OpenStep
format. To test a particular existing project without modifying it, explicitly
select its metadata for a temporary-copy test:

```sh
AGENTVAULT_TEST_XCODE_PROJECT_FILE="/path/to/YourApp.xcodeproj/project.pbxproj" \
  cargo test --locked --test xcode_register_test existing_project_metadata_copy \
  -- --ignored --nocapture
```

The test reads the selected project metadata and writes only to a temporary
copy. It checks parsing, insertion, repeat registration and `plutil` validity;
it does not open Xcode or build the app.

If the command reports that there is no pending session record, first check the
original project path and the AgentVault session ID. Applying a session removes
its pending review record even when the temporary workspace still exists.
Registration cannot reuse that completed session or reconstruct its approval
record from the old files. To register files already applied to your original
project, add their references using Xcode's Add Files action in the original
project. For further sandbox changes, use a newly retained AgentVault session.
