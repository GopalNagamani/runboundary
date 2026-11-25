//! User-level approval flow, isolated with a synthetic host HOME per subprocess.
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Output, Stdio},
};
fn cli(home: &Path, args: &[&str], answer: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_runb"))
        .env("HOME", home)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(answer.as_bytes()) {
        // Invalid-command cases can exit before consuming the approval input.
        // That closes the pipe normally; preserve other write failures.
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    child.wait_with_output().unwrap()
}
fn fake(home: &Path) {
    let base = home.join(".config/manicode");
    std::fs::create_dir_all(&base).unwrap();
    for name in [
        "credentials.json",
        "device-key.json",
        "freebuff",
        "freebuff-metadata.json",
        "message-history.json",
        "settings.json",
    ] {
        let path = base.join(name);
        std::fs::write(&path, "SYNTHETIC_LOGIN_CONTENT").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}
#[test]
fn setup_requires_approval_then_saves_narrow_profile_and_can_revoke() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    fake(&home);
    let saved = home.join(".config/runboundary/auth/freebuff.json");
    for answer in ["", "no\n"] {
        let output = cli(&home, &["auth", "setup", "freebuff"], answer);
        assert!(output.status.success(), "{output:?}");
        assert!(!saved.exists());
    }
    // Auth setup works independently of a valid selected project.
    let output = cli(
        &home,
        &[
            "--project",
            "/nonexistent-project",
            "auth",
            "setup",
            "freebuff",
        ],
        "yes\n",
    );
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("credentials.json"));
    assert!(!stdout.contains("SYNTHETIC_LOGIN_CONTENT"));
    let profile = std::fs::read_to_string(&saved).unwrap();
    assert!(!profile.contains("message-history"));
    assert!(!profile.contains("settings.json"));
    assert!(!profile.contains("SYNTHETIC_LOGIN_CONTENT"));
    assert_eq!(
        std::fs::metadata(&saved).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(saved.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(!cli(&home, &["auth", "setup", "freebuff"], "yes\n")
        .status
        .success());
    assert_eq!(std::fs::read_to_string(&saved).unwrap(), profile);
    assert!(cli(&home, &["auth", "remove", "freebuff"], "")
        .status
        .success());
    assert!(!saved.exists());
    assert!(home.join(".config/manicode/credentials.json").exists());
}
#[test]
fn saved_approval_is_selected_and_bad_profiles_fail_closed_with_opt_out() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    fake(&home);
    assert!(cli(&home, &["auth", "setup", "freebuff"], "y\n")
        .status
        .success());
    let project = home.join("project");
    std::fs::create_dir(&project).unwrap();
    assert!(
        cli(&home, &["--project", project.to_str().unwrap(), "init"], "")
            .status
            .success()
    );
    let output = cli(
        &home,
        &[
            "--project",
            project.to_str().unwrap(),
            "doctor",
            "--agent",
            "freebuff",
        ],
        "",
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Using saved authentication adapter"));
    let saved = home.join(".config/runboundary/auth/freebuff.json");
    std::fs::write(&saved, "INVALID_PRIVATE_PROFILE").unwrap();
    let output = cli(
        &home,
        &[
            "--project",
            project.to_str().unwrap(),
            "doctor",
            "--agent",
            "freebuff",
        ],
        "",
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid adapter manifest"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("INVALID_PRIVATE_PROFILE"));
    let output = cli(
        &home,
        &[
            "--project",
            project.to_str().unwrap(),
            "doctor",
            "--agent",
            "freebuff",
            "--no-saved-auth",
        ],
        "",
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("invalid adapter manifest"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Using saved authentication adapter"));
}
#[test]
fn setup_rejects_unknown_agents_and_nonprivate_login() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    assert!(!cli(&home, &["auth", "setup", "unknown-agent"], "yes\n")
        .status
        .success());
    fake(&home);
    std::fs::set_permissions(
        home.join(".config/manicode/credentials.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(!cli(&home, &["auth", "setup", "freebuff"], "yes\n")
        .status
        .success());
    assert!(!home.join(".config/runboundary/auth/freebuff.json").exists());
}

#[test]
fn hermes_setup_approves_filtered_nous_files_without_copying_secrets_to_profile() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    std::fs::create_dir(home.join(".hermes")).unwrap();
    let auth = home.join(".hermes/auth.json");
    std::fs::write(&auth, r#"{"version":1,"providers":{"nous":{"access_token":"PRIVATE_NOUS_TOKEN"},"other":{"token":"EXCLUDED"}}}"#).unwrap();
    std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(
        home.join(".hermes/config.yaml"),
        "model:\n  provider: nous\n  default: example-free-model\nhooks: EXCLUDED\n",
    )
    .unwrap();
    assert!(cli(&home, &["auth", "setup", "hermes"], "no\n")
        .status
        .success());
    assert!(!home.join(".config/runboundary/auth/hermes.json").exists());
    let output = cli(&home, &["auth", "setup", "hermes"], "yes\n");
    assert!(output.status.success(), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE_NOUS_TOKEN"));
    let path = home.join(".config/runboundary/auth/hermes.json");
    let manifest = std::fs::read_to_string(&path).unwrap();
    assert!(manifest.contains("hermes_nous_auth"));
    assert!(!manifest.contains("PRIVATE_NOUS_TOKEN"));
    let adapter = runboundary::security::auth_adapter::Adapter::load(&path, "hermes").unwrap();
    let private = tempfile::tempdir().unwrap();
    adapter.import(private.path()).unwrap();
    let imported = std::fs::read_to_string(private.path().join(".hermes/auth.json")).unwrap();
    assert!(imported.contains("PRIVATE_NOUS_TOKEN"));
    assert!(!imported.contains("EXCLUDED"));
    assert!(
        !std::fs::read_to_string(private.path().join(".hermes/config.yaml"))
            .unwrap()
            .contains("EXCLUDED")
    );
    assert!(cli(&home, &["auth", "remove", "hermes"], "")
        .status
        .success());
    assert!(auth.exists());
}

#[test]
fn setup_batches_builtin_agents_with_one_approval_and_cancels_as_a_unit() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    fake(&home);
    std::fs::create_dir(home.join(".hermes")).unwrap();
    std::fs::write(
        home.join(".hermes/auth.json"),
        r#"{"version":1,"providers":{"nous":{"access_token":"PRIVATE_NOUS_TOKEN"}}}"#,
    )
    .unwrap();
    std::fs::set_permissions(
        home.join(".hermes/auth.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(
        home.join(".hermes/config.yaml"),
        "model:\n  provider: nous\n  default: example-model\n",
    )
    .unwrap();

    let args = ["auth", "setup", "freebuff", "hermes"];
    let output = cli(&home, &args, "no\n");
    assert!(output.status.success(), "{output:?}");
    assert!(!home.join(".config/runboundary/auth/freebuff.json").exists());
    assert!(!home.join(".config/runboundary/auth/hermes.json").exists());

    let output = cli(&home, &args, "yes\n");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("freebuff:"));
    assert!(stdout.contains("hermes:"));
    assert!(stdout.contains("Save all approvals? [y/N]"));
    assert!(!stdout.contains("PRIVATE_NOUS_TOKEN"));
    for agent in ["freebuff", "hermes"] {
        let path = home
            .join(".config/runboundary/auth")
            .join(format!("{agent}.json"));
        assert!(path.exists(), "missing saved approval for {agent}");
        let profile = std::fs::read_to_string(path).unwrap();
        assert!(!profile.contains("PRIVATE_NOUS_TOKEN"));
    }
}

#[test]
fn setup_batch_refuses_duplicates_existing_profiles_and_custom_adapter_mix() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().canonicalize().unwrap();
    fake(&home);
    let output = cli(&home, &["auth", "setup", "freebuff", "freebuff"], "yes\n");
    assert!(!output.status.success());
    assert!(!home.join(".config/runboundary/auth/freebuff.json").exists());

    std::fs::create_dir(home.join(".hermes")).unwrap();
    std::fs::write(
        home.join(".hermes/auth.json"),
        r#"{"version":1,"providers":{"nous":{"access_token":"TOKEN"}}}"#,
    )
    .unwrap();
    std::fs::set_permissions(
        home.join(".hermes/auth.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(
        home.join(".hermes/config.yaml"),
        "model:\n  provider: nous\n  default: example-model\n",
    )
    .unwrap();

    let saved_dir = home.join(".config/runboundary/auth");
    std::fs::create_dir_all(&saved_dir).unwrap();
    std::fs::set_permissions(&saved_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(saved_dir.join("hermes.json"), "existing").unwrap();
    let output = cli(&home, &["auth", "setup", "freebuff", "hermes"], "yes\n");
    assert!(!output.status.success());
    assert!(!saved_dir.join("freebuff.json").exists());

    let output = cli(
        &home,
        &[
            "auth",
            "setup",
            "freebuff",
            "hermes",
            "--adapter",
            "/tmp/adapter.json",
        ],
        "yes\n",
    );
    assert!(!output.status.success());
}
