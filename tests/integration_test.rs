use agentvault::{
    policy::{config::Config, matcher::Matcher},
    security::paths::Dir,
    workspace::{prepare, sync},
};
use std::{path::Path, process::Command};
#[test]
fn init_valid_and_no_overwrite() {
    let p = tempfile::tempdir().unwrap();
    std::fs::write(p.path().join(".env"), "DO_NOT_PRINT_FAKE_SECRET").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_agentvault"))
        .args(["--project", p.path().to_str().unwrap(), "init"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("DO_NOT_PRINT_FAKE_SECRET"));
    let config = Config::load(p.path()).unwrap();
    assert_eq!(
        config.sandbox.backend,
        if cfg!(target_os = "macos") {
            "seatbelt"
        } else {
            "bubblewrap"
        }
    );
    assert!(!Command::new(env!("CARGO_BIN_EXE_agentvault"))
        .args(["--project", p.path().to_str().unwrap(), "init"])
        .status()
        .unwrap()
        .success());
}
#[test]
fn synchronization_protects_secrets_and_detects_host_edits() {
    let p = tempfile::tempdir().unwrap();
    std::fs::write(p.path().join("source"), "before").unwrap();
    std::fs::write(p.path().join(".env"), "fake").unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let root = Dir::open(p.path()).unwrap();
    let work = prepare::prepare(&root, &m).unwrap();
    let out = Dir::open(work.path()).unwrap();
    std::fs::write(work.path().join("source"), "after").unwrap();
    let reviewed = prepare::snapshot(&out, &m, true).unwrap();
    std::fs::write(work.path().join(".env"), "attack").unwrap();
    assert!(sync::apply(p.path(), &root, &out, &work.baseline, &reviewed, &m).is_err());
    assert_eq!(std::fs::read(p.path().join(".env")).unwrap(), b"fake");
    std::fs::remove_file(work.path().join(".env")).unwrap();
    std::fs::write(p.path().join("source"), "concurrent edit").unwrap();
    assert!(sync::apply(p.path(), &root, &out, &work.baseline, &reviewed, &m).is_err());
}
#[test]
fn synchronization_add_modify_delete_and_recovery() {
    let p = tempfile::tempdir().unwrap();
    std::fs::write(p.path().join("source"), "before").unwrap();
    std::fs::write(p.path().join("delete"), "old").unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let root = Dir::open(p.path()).unwrap();
    let work = prepare::prepare(&root, &m).unwrap();
    let out = Dir::open(work.path()).unwrap();
    std::fs::write(work.path().join("source"), "after").unwrap();
    std::fs::remove_file(work.path().join("delete")).unwrap();
    std::fs::create_dir(work.path().join("new")).unwrap();
    std::fs::write(work.path().join("new/file"), "added").unwrap();
    let reviewed = prepare::snapshot(&out, &m, true).unwrap();
    let recovery = sync::apply(p.path(), &root, &out, &work.baseline, &reviewed, &m)
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read(p.path().join("source")).unwrap(), b"after");
    assert!(!p.path().join("delete").exists());
    assert_eq!(
        std::fs::read(recovery.join("originals/source")).unwrap(),
        b"before"
    );
    assert!(p.path().join("new/file").exists());
    assert!(Path::new(&recovery).join("journal.jsonl").exists());
}
#[test]
fn startup_failure_never_executes_host_command() {
    let p = tempfile::tempdir().unwrap();
    std::fs::write(
        p.path().join("agentvault.yaml"),
        agentvault::policy::config::DEFAULT,
    )
    .unwrap();
    let marker = p.path().join("launched");
    let result = Command::new(env!("CARGO_BIN_EXE_agentvault"))
        .args([
            "--project",
            p.path().to_str().unwrap(),
            "run",
            "--",
            "sh",
            "-c",
            &format!("touch {}", marker.display()),
        ])
        .output()
        .unwrap();
    // Linux may support the sandbox: even then host marker must remain inaccessible.
    assert!(!marker.exists());
    #[cfg(not(target_os = "linux"))]
    assert!(!result.status.success());
    #[cfg(target_os = "linux")]
    let _ = result;
}

#[test]
fn retained_review_preview_and_explicit_approval() {
    let p = tempfile::tempdir().unwrap();
    std::fs::write(
        p.path().join("agentvault.yaml"),
        agentvault::policy::config::DEFAULT,
    )
    .unwrap();
    std::fs::write(p.path().join("source"), "before").unwrap();
    std::fs::write(p.path().join(".env"), "FAKE_HOST_SECRET_NOT_IN_PREVIEW").unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let root = Dir::open(p.path()).unwrap();
    let work = prepare::prepare(&root, &m).unwrap();
    std::fs::write(work.path().join("source"), "after\u{1b}[31m").unwrap();
    agentvault::security::audit::log(p.path(), "test", "synthetic review fixture").unwrap();
    let workspace = work.path().to_owned();
    let _ = work.temp.keep();
    let id = agentvault::cli::review::retain(p.path(), workspace.clone(), work.baseline).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_agentvault"))
        .args([
            "--project",
            p.path().to_str().unwrap(),
            "review",
            &id,
            "--diff",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let preview = String::from_utf8(output.stdout).unwrap();
    assert!(!preview.contains("FAKE_HOST_SECRET_NOT_IN_PREVIEW"));
    assert!(!preview.contains('\u{1b}'));
    assert_eq!(std::fs::read(p.path().join("source")).unwrap(), b"before");
    agentvault::cli::review::execute(p.path(), &id, true, false).unwrap();
    assert_eq!(
        std::fs::read(p.path().join("source")).unwrap(),
        b"after\x1b[31m"
    );
    std::fs::remove_dir_all(workspace.parent().unwrap()).unwrap();
}

#[test]
fn sync_failure_rolls_back_and_retains_originals() {
    let p = tempfile::tempdir().unwrap();
    std::fs::write(p.path().join("a"), "before").unwrap();
    std::fs::create_dir(p.path().join("z")).unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let root = Dir::open(p.path()).unwrap();
    let work = prepare::prepare(&root, &m).unwrap();
    std::fs::write(work.path().join("a"), "after").unwrap();
    std::fs::remove_dir(work.path().join("z")).unwrap();
    std::fs::write(work.path().join("z"), "conflicting file").unwrap();
    let out = Dir::open(work.path()).unwrap();
    let reviewed = prepare::snapshot(&out, &m, true).unwrap();
    assert!(sync::apply(p.path(), &root, &out, &work.baseline, &reviewed, &m).is_err());
    assert_eq!(std::fs::read(p.path().join("a")).unwrap(), b"before");
    assert!(p.path().join("z").is_dir());
    assert!(std::fs::read_dir(p.path()).unwrap().any(|p| p
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".agentvault-recovery-")));
}

#[test]
fn authentication_is_explicit_and_tokens_are_not_arguments() {
    use agentvault::sandbox::process::agent_entrypoint;
    use std::collections::BTreeMap;
    let mut env = BTreeMap::new();
    env.insert("OPENAI_API_KEY".into(), "SYNTHETIC_NOT_REAL_TOKEN".into());
    let (_exe, args) = agent_entrypoint(
        "codex",
        Path::new("/usr/bin/codex"),
        &["hello; harmless argument".into()],
        &env,
    )
    .unwrap();
    assert!(!args.iter().any(|s| s.contains("SYNTHETIC_NOT_REAL_TOKEN")));
    assert_eq!(args.last().unwrap(), "hello; harmless argument");
}

#[test]
fn agents_and_local_codex_models_do_not_require_provider_credentials() {
    use agentvault::sandbox::process::agent_entrypoint;
    let env = std::collections::BTreeMap::new();
    let local_args: Vec<String> = ["--oss", "--local-provider", "ollama", "-m", "example-model"]
        .map(String::from)
        .to_vec();
    let (executable, args) = agent_entrypoint(
        "codex",
        Path::new("/usr/local/bin/codex"),
        &local_args,
        &env,
    )
    .unwrap();
    assert_eq!(executable, Path::new("/usr/local/bin/codex"));
    assert!(args.ends_with(&local_args));
    assert!(!args
        .iter()
        .any(|arg| arg == "login" || arg == "--with-api-key"));
    for name in ["claude", "self-hosted-agent"] {
        let arguments = vec!["--endpoint=http://localhost:8000".to_owned()];
        let (_, planned) =
            agent_entrypoint(name, Path::new("/usr/local/bin/agent"), &arguments, &env).unwrap();
        assert_eq!(planned, arguments);
    }
}

#[test]
fn chatgpt_auth_is_explicit_and_conflicts_with_api_key_approval() {
    use agentvault::cli::Cli;
    use clap::Parser;
    assert!(Cli::try_parse_from([
        "agentvault",
        "run",
        "--codex-auth-file",
        "/example/auth.json",
        "--auth-env",
        "OPENAI_API_KEY",
        "--",
        "codex"
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "agentvault",
        "doctor",
        "--codex-auth-file",
        "/example/auth.json"
    ])
    .is_ok());
    assert!(agentvault::security::codex_auth::validate_agent("claude").is_err());
    let env = std::collections::BTreeMap::new();
    let (_, args) = agentvault::sandbox::process::agent_entrypoint_with_auth(
        "codex",
        Path::new("/usr/bin/codex"),
        &[],
        &env,
        true,
    )
    .unwrap();
    assert!(args
        .iter()
        .any(|v| v == "cli_auth_credentials_store=\"file\""));
    assert!(agentvault::sandbox::process::agent_entrypoint_with_auth(
        "claude",
        Path::new("/usr/bin/claude"),
        &[],
        &env,
        true,
    )
    .is_err());
}
