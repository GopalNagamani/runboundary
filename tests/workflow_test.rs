//! CLI lifecycle regression coverage; portable tests do not establish OS isolation.
use runboundary::{
    cli::review,
    policy::{config::Config, matcher::Matcher},
    security::{audit, paths::Dir},
    workspace::prepare,
};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
fn cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_runb"))
        .arg("--project")
        .arg(root)
        .args(args)
        .output()
        .unwrap()
}
struct Session {
    root: tempfile::TempDir,
    workspace: PathBuf,
    id: String,
}
impl Session {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        assert!(cli(root.path(), &["init"]).status.success());
        std::fs::write(root.path().join("source.txt"), "original\n").unwrap();
        std::fs::write(root.path().join("delete.txt"), "remove\n").unwrap();
        std::fs::write(root.path().join(".env"), "SYNTHETIC_PRIVATE_CANARY").unwrap();
        let matcher = Matcher::new(&Config::load(root.path()).unwrap()).unwrap();
        let work = prepare::prepare(&Dir::open(root.path()).unwrap(), &matcher).unwrap();
        assert!(!work.path().join(".env").exists());
        std::fs::write(work.path().join("source.txt"), "edited\n").unwrap();
        std::fs::remove_file(work.path().join("delete.txt")).unwrap();
        std::fs::create_dir(work.path().join("new")).unwrap();
        std::fs::write(work.path().join("new/added.txt"), "added\n").unwrap();
        audit::log(root.path(), "test", "synthetic CLI workflow").unwrap();
        let workspace = work.path().to_owned();
        let _ = work.temp.keep();
        let id = review::retain(root.path(), workspace.clone(), work.baseline).unwrap();
        Self {
            root,
            workspace,
            id,
        }
    }
    fn command(&self, flag: &str) -> Output {
        cli(self.root.path(), &["review", &self.id, flag])
    }
    fn pending(&self) -> bool {
        self.root
            .path()
            .join(format!(".runboundary/review-{}.json", self.id))
            .exists()
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.workspace.parent().unwrap());
    }
}
#[test]
fn cli_review_apply_and_recovery_lifecycle() {
    let s = Session::new();
    for _ in 0..2 {
        let out = s.command("--review");
        assert!(out.status.success(), "{out:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        for kind in ["added", "modified", "deleted"] {
            assert!(text.contains(kind));
        }
        assert!(!text.contains("SYNTHETIC_PRIVATE_CANARY"));
        assert_eq!(
            std::fs::read(s.root.path().join("source.txt")).unwrap(),
            b"original\n"
        );
        assert!(s.pending());
    }
    let applied = s.command("--apply");
    assert!(applied.status.success(), "{applied:?}");
    assert!(!s.pending());
    assert_eq!(
        std::fs::read(s.root.path().join("source.txt")).unwrap(),
        b"edited\n"
    );
    assert_eq!(
        std::fs::read(s.root.path().join("new/added.txt")).unwrap(),
        b"added\n"
    );
    assert!(!s.root.path().join("delete.txt").exists());
    let recovery = std::fs::read_dir(s.root.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".runboundary-recovery-")
        })
        .unwrap();
    assert_eq!(
        std::fs::read(recovery.join("originals/source.txt")).unwrap(),
        b"original\n"
    );
    assert_eq!(
        std::fs::read(recovery.join("originals/delete.txt")).unwrap(),
        b"remove\n"
    );
    assert!(std::fs::read_to_string(recovery.join("journal.jsonl"))
        .unwrap()
        .contains("complete"));
    assert!(!s.command("--apply").status.success());
}

#[test]
fn recover_command_leaves_a_completed_apply_unchanged() {
    let s = Session::new();
    let applied = s.command("--apply");
    assert!(applied.status.success(), "{applied:?}");
    let recovery_dir = std::fs::read_dir(s.root.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(".runboundary-recovery-")
        })
        .unwrap();
    let name = recovery_dir.file_name().unwrap().to_str().unwrap();
    let out = cli(s.root.path(), &["recover", name]);
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("already complete or recovered"));
    assert_eq!(
        std::fs::read(s.root.path().join("source.txt")).unwrap(),
        b"edited\n"
    );
}

#[test]
fn recover_command_rolls_back_an_interrupted_version_two_journal() {
    let root = tempfile::tempdir().unwrap();
    assert!(cli(root.path(), &["init"]).status.success());
    let root_path = root.path().canonicalize().unwrap();
    let before = b"before crash\n";
    let after = b"agent output\n";
    std::fs::write(root_path.join("source.txt"), after).unwrap();
    let recovery = root_path.join(".runboundary-recovery-cli-test");
    std::fs::create_dir(&recovery).unwrap();
    std::fs::create_dir(recovery.join("originals")).unwrap();
    std::fs::create_dir(recovery.join("staged")).unwrap();
    for path in [
        recovery.clone(),
        recovery.join("originals"),
        recovery.join("staged"),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(recovery.join("originals/source.txt"), before).unwrap();
    let expected = |bytes: &[u8]| {
        serde_json::json!({
            "hash": Sha256::digest(bytes).to_vec(),
            "mode": 0o600,
            "link_target": null
        })
    };
    let record = serde_json::json!({
        "type": "intent",
        "version": 2,
        "path": "source.txt",
        "original": expected(before),
        "desired": expected(after)
    });
    let journal = recovery.join("journal.jsonl");
    std::fs::write(&journal, format!("{record}\n")).unwrap();
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();

    let recovery_arg = recovery.to_str().unwrap();
    let recovered = cli(root.path(), &["recover", recovery_arg]);
    assert!(recovered.status.success(), "{recovered:?}");
    assert_eq!(std::fs::read(root_path.join("source.txt")).unwrap(), before);
    let repeated = cli(root.path(), &["recover", ".runboundary-recovery-cli-test"]);
    assert!(repeated.status.success(), "{repeated:?}");
    assert!(String::from_utf8_lossy(&repeated.stdout).contains("already complete or recovered"));
}

#[test]
fn review_redacts_credential_like_values_and_warns() {
    let s = Session::new();
    let credential = "sk-live-SYNTHETIC_ONLY_credential_value";
    std::fs::write(
        s.workspace.join("source.txt"),
        format!("OPENAI_API_KEY={credential}\nordinary source\n"),
    )
    .unwrap();
    let output = s.command("--diff");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(credential));
    assert!(stdout.contains("OPENAI_API_KEY=[REDACTED]"));
    assert!(stdout.contains("possible credential-like content was detected"));
    assert!(stdout.contains("ordinary source"));
}
#[test]
fn stale_source_refuses_review_and_apply_without_losing_session() {
    let s = Session::new();
    assert!(s.command("--diff").status.success());
    std::fs::write(
        s.root.path().join("source.txt"),
        "PRIVATE_NEW_SOURCE_CONTENT",
    )
    .unwrap();
    for flag in ["--diff", "--apply"] {
        let out = s.command(flag);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("host project changed"));
        assert!(!String::from_utf8_lossy(&out.stdout).contains("PRIVATE_NEW_SOURCE_CONTENT"));
        assert!(s.pending());
        assert!(!s.root.path().join("new/added.txt").exists());
        assert!(s.root.path().join("delete.txt").exists());
    }
}
#[test]
fn unsafe_agent_output_refuses_review_and_apply_without_touching_source() {
    let s = Session::new();
    std::fs::write(s.workspace.join(".env"), "SYNTHETIC_INJECTED_SECRET").unwrap();
    for flag in ["--diff", "--apply"] {
        let out = s.command(flag);
        assert!(!out.status.success());
        assert!(!String::from_utf8_lossy(&out.stdout).contains("SYNTHETIC_INJECTED_SECRET"));
        assert!(s.pending());
        assert_eq!(
            std::fs::read(s.root.path().join("source.txt")).unwrap(),
            b"original\n"
        );
    }
    std::fs::remove_file(s.workspace.join(".env")).unwrap();
    assert!(s.command("--diff").status.success());
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "REAL native CLI lifecycle: mandatory Seatbelt preflight; run from Terminal"]
fn native_agent_run_retains_edits_on_failure_then_reviews_and_applies() {
    let root = tempfile::tempdir().unwrap();
    assert!(cli(root.path(), &["init"]).status.success());
    std::fs::write(root.path().join("source.txt"), "original\n").unwrap();
    std::fs::write(root.path().join(".env"), "SYNTHETIC_HOST_SECRET").unwrap();
    // Shell substitutes for a coding agent: no provider credentials or requests.
    // Exit 7 proves --apply never applies automatically after a failed agent.
    let original_secret = root.path().join(".env");
    let run = cli(root.path(), &[
        "run", "--apply", "--", "sh", "-c",
        "test ! -e .env || exit 91; if cat \"$1\" >/dev/null 2>&1; then exit 92; fi; printf 'edited\\n' > source.txt; printf 'added\\n' > added.txt; exit 7",
        "runboundary-workflow-test", original_secret.to_str().unwrap(),
    ]);
    assert_eq!(
        run.status.code(),
        Some(7),
        "native launch/preflight failed: {run:?}"
    );
    assert_eq!(
        std::fs::read(root.path().join("source.txt")).unwrap(),
        b"original\n"
    );
    let stdout = String::from_utf8_lossy(&run.stdout);
    let id = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Review: runb diff "))
        .expect("retained session ID");
    let record_path = root.path().join(format!(".runboundary/review-{id}.json"));
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    let workspace = PathBuf::from(record["workspace"].as_str().unwrap());
    let session = Session {
        root,
        workspace,
        id: id.to_owned(),
    };
    assert!(!session
        .workspace
        .parent()
        .unwrap()
        .join("sandbox-home")
        .exists());
    assert!(!session
        .workspace
        .parent()
        .unwrap()
        .join("sandbox-tmp")
        .exists());
    let reviewed = session.command("--diff");
    assert!(reviewed.status.success(), "{reviewed:?}");
    assert!(!String::from_utf8_lossy(&reviewed.stdout).contains("SYNTHETIC_HOST_SECRET"));
    let applied = session.command("--apply");
    assert!(applied.status.success(), "{applied:?}");
    assert_eq!(
        std::fs::read(session.root.path().join("source.txt")).unwrap(),
        b"edited\n"
    );
    assert_eq!(
        std::fs::read(session.root.path().join("added.txt")).unwrap(),
        b"added\n"
    );
    assert!(!session.pending());
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "REAL native CLI successful apply: mandatory Seatbelt preflight; run from Terminal"]
fn native_successful_agent_applies_only_with_explicit_advance_approval() {
    let root = tempfile::tempdir().unwrap();
    assert!(cli(root.path(), &["init"]).status.success());
    std::fs::write(root.path().join("source.txt"), "original\n").unwrap();
    let run = cli(
        root.path(),
        &[
            "run",
            "--apply",
            "--",
            "sh",
            "-c",
            "printf 'edited\\n' > source.txt; printf 'added\\n' > added.txt",
        ],
    );
    assert!(run.status.success(), "native launch/apply failed: {run:?}");
    assert_eq!(
        std::fs::read(root.path().join("source.txt")).unwrap(),
        b"edited\n"
    );
    assert_eq!(
        std::fs::read(root.path().join("added.txt")).unwrap(),
        b"added\n"
    );
    assert!(String::from_utf8_lossy(&run.stdout).contains("Recovery originals"));
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "REAL native CLI signal exit: mandatory Seatbelt preflight; run from Terminal"]
fn native_signalled_agent_retains_changes_without_applying() {
    let root = tempfile::tempdir().unwrap();
    assert!(cli(root.path(), &["init"]).status.success());
    std::fs::write(root.path().join("source.txt"), "original\n").unwrap();
    let run = cli(
        root.path(),
        &[
            "run",
            "--apply",
            "--",
            "sh",
            "-c",
            "printf 'interrupted edit\\n' > source.txt; kill -TERM $$",
        ],
    );
    assert_eq!(run.status.code(), Some(128 + libc::SIGTERM), "{run:?}");
    assert_eq!(
        std::fs::read(root.path().join("source.txt")).unwrap(),
        b"original\n"
    );
    let stdout = String::from_utf8_lossy(&run.stdout);
    let id = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Review: runb diff "))
        .expect("retained session");
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.path().join(format!(".runboundary/review-{id}.json"))).unwrap(),
    )
    .unwrap();
    let session = Session {
        workspace: PathBuf::from(record["workspace"].as_str().unwrap()),
        root,
        id: id.to_owned(),
    };
    assert!(session.pending());
    assert!(session.command("--diff").status.success());
    assert_eq!(
        std::fs::read(session.workspace.join("source.txt")).unwrap(),
        b"interrupted edit\n"
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "REAL generic adapter lifecycle: mandatory Seatbelt preflight; synthetic credentials only; run from Terminal"]
fn native_generic_adapter_imports_only_approved_files_and_discards_copies() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    assert!(cli(root.path(), &["init"]).status.success());
    let approved = tempfile::tempdir().unwrap();
    let base = approved.path().canonicalize().unwrap();
    let login = base.join("login.json");
    std::fs::write(&login, "SYNTHETIC_ADAPTER_LOGIN").unwrap();
    std::fs::set_permissions(&login, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(base.join("unapproved"), "SYNTHETIC_NOT_APPROVED").unwrap();
    let manifest = base.join("adapter.json");
    std::fs::write(&manifest, serde_json::to_vec(&serde_json::json!({"version":1,"agent":"sh","files":[{"source":login,"destination":".config/example/login.json"}]})).unwrap()).unwrap();
    std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(0o600)).unwrap();
    let checked = cli(
        root.path(),
        &[
            "doctor",
            "--agent",
            "sh",
            "--auth-adapter",
            manifest.to_str().unwrap(),
        ],
    );
    assert!(checked.status.success(), "{checked:?}");
    // Save custom approval once, then launch with no authentication flag.
    use std::io::Write;
    use std::process::Stdio;
    let mut setup = Command::new(env!("CARGO_BIN_EXE_runb"))
        .env("HOME", &base)
        .args([
            "auth",
            "setup",
            "sh",
            "--adapter",
            manifest.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    setup.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    let setup = setup.wait_with_output().unwrap();
    assert!(setup.status.success(), "{setup:?}");
    let run = Command::new(env!("CARGO_BIN_EXE_runb"))
        .env("HOME", &base).arg("--project").arg(root.path())
        .args(["run", "--", "sh", "-c", "test \"$(cat \"$HOME/.config/example/login.json\")\" = SYNTHETIC_ADAPTER_LOGIN || exit 91; test ! -e \"$HOME/unapproved\" || exit 92; printf 'rotated' > \"$HOME/.config/example/login.json\"; printf 'edited' > source.txt"])
        .output().unwrap();
    assert!(run.status.success(), "{run:?}");
    assert_eq!(std::fs::read(&login).unwrap(), b"SYNTHETIC_ADAPTER_LOGIN");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(!stdout.contains("SYNTHETIC_ADAPTER_LOGIN"));
    let id = stdout
        .lines()
        .find_map(|line| line.strip_prefix("Review: runb diff "))
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(root.path().join(format!(".runboundary/review-{id}.json"))).unwrap(),
    )
    .unwrap();
    let session = Session {
        workspace: PathBuf::from(record["workspace"].as_str().unwrap()),
        root,
        id: id.to_owned(),
    };
    assert!(!session
        .workspace
        .parent()
        .unwrap()
        .join("sandbox-home")
        .exists());
    assert!(session.command("--apply").status.success());
    assert_eq!(
        std::fs::read(session.root.path().join("source.txt")).unwrap(),
        b"edited"
    );
    assert!(!session
        .root
        .path()
        .join(".config/example/login.json")
        .exists());
}

#[test]
fn adapter_cli_rejects_ambiguous_authentication() {
    use clap::Parser;
    use runboundary::cli::Cli;
    for command in ["doctor", "run"] {
        let mut args = vec![
            "runb",
            command,
            "--auth-adapter",
            "/private/adapter.json",
            "--codex-auth-file",
            "/private/auth.json",
        ];
        if command == "run" {
            args.extend(["--", "codex"]);
        }
        assert!(Cli::try_parse_from(args).is_err());
    }
    assert!(Cli::try_parse_from([
        "runb",
        "run",
        "--auth-adapter",
        "/private/adapter.json",
        "--auth-env",
        "OPENAI_API_KEY",
        "--",
        "codex"
    ])
    .is_err());
}
