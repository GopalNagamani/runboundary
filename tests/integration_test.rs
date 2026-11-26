use runboundary::{
    policy::{config::Config, matcher::Matcher},
    security::paths::Dir,
    workspace::{prepare, sync},
};
use std::{path::Path, process::Command};
#[test]
fn init_valid_and_no_overwrite() {
    let p = tempfile::tempdir().unwrap();
    std::fs::write(p.path().join(".env"), "DO_NOT_PRINT_FAKE_SECRET").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_runb"))
        .args(["--project", p.path().to_str().unwrap(), "init"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("DO_NOT_PRINT_FAKE_SECRET"));
    assert!(p.path().join("runboundary.yaml").is_file());
    assert!(!p.path().join("agentvault.yaml").exists());
    let config = Config::load(p.path()).unwrap();
    assert_eq!(
        config.sandbox.backend,
        if cfg!(target_os = "macos") {
            "seatbelt"
        } else {
            "bubblewrap"
        }
    );
    assert!(!Command::new(env!("CARGO_BIN_EXE_runb"))
        .args(["--project", p.path().to_str().unwrap(), "init"])
        .status()
        .unwrap()
        .success());
}

#[test]
fn init_preserves_policy_from_before_the_rename() {
    let project = tempfile::tempdir().unwrap();
    let config_path = project.path().join("runboundary.yaml");
    let legacy_path = project.path().join("agentvault.yaml");
    let mut config = Config::for_host();
    config.filesystem.protected.push("private".into());
    std::fs::write(&legacy_path, serde_yaml::to_string(&config).unwrap()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_runb"))
        .args(["--project", project.path().to_str().unwrap(), "init"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("rename it to runboundary.yaml"));
    assert!(!config_path.exists());

    std::fs::rename(legacy_path, config_path).unwrap();
    let config = Config::load(project.path()).unwrap();
    assert!(Matcher::new(&config)
        .unwrap()
        .protected(Path::new("private")));
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
        p.path().join("runboundary.yaml"),
        runboundary::policy::config::DEFAULT,
    )
    .unwrap();
    let marker = p.path().join("launched");
    let result = Command::new(env!("CARGO_BIN_EXE_runb"))
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
        p.path().join("runboundary.yaml"),
        runboundary::policy::config::DEFAULT,
    )
    .unwrap();
    std::fs::write(p.path().join("source"), "before").unwrap();
    std::fs::write(p.path().join(".env"), "FAKE_HOST_SECRET_NOT_IN_PREVIEW").unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let root = Dir::open(p.path()).unwrap();
    let work = prepare::prepare(&root, &m).unwrap();
    std::fs::write(work.path().join("source"), "after\u{1b}[31m").unwrap();
    runboundary::security::audit::log(p.path(), "test", "synthetic review fixture").unwrap();
    let workspace = work.path().to_owned();
    let _ = work.temp.keep();
    let id = runboundary::cli::review::retain(p.path(), workspace.clone(), work.baseline).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_runb"))
        .current_dir(p.path())
        .args(["diff", &id])
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
    assert!(Command::new(env!("CARGO_BIN_EXE_runb"))
        .current_dir(p.path())
        .args(["apply", &id])
        .output()
        .unwrap()
        .status
        .success());
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
        .starts_with(".runboundary-recovery-")));
}

#[test]
fn authentication_is_explicit_and_tokens_are_not_arguments() {
    use runboundary::sandbox::process::agent_entrypoint;
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
    use runboundary::sandbox::process::agent_entrypoint;
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
    use clap::Parser;
    use runboundary::cli::Cli;
    assert!(Cli::try_parse_from([
        "runb",
        "run",
        "--codex-auth-file",
        "/example/auth.json",
        "--auth-env",
        "OPENAI_API_KEY",
        "--",
        "codex"
    ])
    .is_err());
    assert!(
        Cli::try_parse_from(["runb", "doctor", "--codex-auth-file", "/example/auth.json"]).is_ok()
    );
    assert!(Cli::try_parse_from(["runb", "doctor", "--chatgpt"]).is_ok());
    assert!(Cli::try_parse_from(["runb", "doctor", "sh"]).is_ok());
    assert!(Cli::try_parse_from(["runb", "doctor", "sh", "--agent", "codex"]).is_err());
    assert!(Cli::try_parse_from([
        "runb",
        "run",
        "--chatgpt",
        "--codex-auth-file",
        "/example/auth.json",
        "codex"
    ])
    .is_err());
    assert!(runboundary::security::codex_auth::validate_agent("claude").is_err());
    let env = std::collections::BTreeMap::new();
    let (_, args) = runboundary::sandbox::process::agent_entrypoint_with_auth(
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
    if cfg!(target_os = "macos") {
        assert!(
            args.ends_with(&["--no-daemon", "--sandbox", "danger-full-access"].map(String::from))
        );
    }
    assert!(Cli::try_parse_from(["runb", "run"]).is_err());
    for name in ["codex", "claude", "hermes", "sh"] {
        assert!(matches!(
            Cli::try_parse_from(["runb", "run", name]).unwrap().command,
            runboundary::cli::Commands::Run { agent, chatgpt: false, .. } if agent == [name]
        ));
    }
    assert!(runboundary::sandbox::process::agent_entrypoint_with_auth(
        "claude",
        Path::new("/usr/bin/claude"),
        &[],
        &env,
        true,
    )
    .is_err());
}

#[test]
fn agent_options_never_opt_into_runboundary_approval() {
    use clap::Parser;
    use runboundary::cli::{Cli, Commands};

    for argv in [
        &[
            "runb",
            "run",
            "--chatgpt",
            "codex",
            "--apply",
            "--project",
            "child",
        ][..],
        &[
            "runb",
            "run",
            "--chatgpt",
            "--",
            "codex",
            "--apply",
            "--project",
            "child",
        ][..],
    ] {
        let cli = Cli::try_parse_from(argv).unwrap();
        assert_eq!(cli.project, Path::new("."));
        let Commands::Run {
            apply,
            chatgpt,
            agent,
            ..
        } = cli.command
        else {
            panic!("expected run")
        };
        assert!(!apply);
        assert!(chatgpt);
        assert_eq!(agent, ["codex", "--apply", "--project", "child"]);
    }
}
