mod common;
use common::*;
#[test]
#[ignore = "REAL OS SECURITY TEST: requires unprivileged Linux and working Bubblewrap"]
fn direct_secret_reads_denied() {
    let f = Fixture::new();
    successful(f.shell("! cat /workspace/.env && ! cat /workspace/.env.production"));
}
#[test]
#[ignore = "REAL OS SECURITY TEST: additionally requires root-owned Python 3 installation"]
fn python_secret_read_denied() {
    let f = Fixture::new();
    successful(f.exec("python3",&["-c","import pathlib; p=pathlib.Path('/workspace/.env'); assert not p.exists();\ntry: p.read_text()\nexcept FileNotFoundError: pass\nelse: raise AssertionError('secret visible')"]));
}
#[test]
#[ignore = "REAL OS SECURITY TEST: additionally requires root-owned Node.js installation"]
fn node_secret_read_denied() {
    let f = Fixture::new();
    successful(f.exec("node",&["-e","try { require('fs').readFileSync('/workspace/.env'); process.exit(1); } catch(e) { if(e.code !== 'ENOENT') process.exit(2); }"]));
}
#[test]
#[ignore = "REAL OS SECURITY TEST: requires unprivileged Linux and working Bubblewrap"]
fn template_read_and_source_edit_allowed() {
    let f = Fixture::new();
    successful(f.shell("grep -q template .env.example && printf edited > source.txt"));
    assert_eq!(
        std::fs::read(f.work.path().join("source.txt")).unwrap(),
        b"edited"
    );
    assert_eq!(
        std::fs::read(f.project.path().join("source.txt")).unwrap(),
        b"original\n"
    );
}
#[test]
#[ignore = "REAL OS SECURITY TEST: requires unprivileged Linux and working Bubblewrap"]
fn host_project_credentials_and_docker_inaccessible() {
    let f = Fixture::new();
    let original = f.project.path().join(".env").to_string_lossy().into_owned();
    successful(f.exec("sh",&["-c","! cat \"$1\" && ! cat /root/.ssh/id_rsa && ! cat /root/.aws/credentials && test ! -e /var/run/docker.sock && test ! -e /run/docker.sock","probe",&original]));
    for relative in [".ssh/id_rsa", ".aws/credentials", "docker.sock"] {
        let p = f.host_canaries.path().join(relative);
        assert!(p.exists(), "fixture must exist outside sandbox");
        successful(f.exec(
            "sh",
            &["-c", "test ! -e \"$1\"", "probe", p.to_str().unwrap()],
        ));
    }
    // Check the actual invoking user's credential paths as well (no contents read on host).
    if let Some(home) = std::env::var_os("HOME") {
        for relative in [".ssh/id_rsa", ".aws/credentials"] {
            let p = std::path::PathBuf::from(&home).join(relative);
            successful(f.exec(
                "sh",
                &["-c", "test ! -e \"$1\"", "probe", p.to_str().unwrap()],
            ));
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "REAL OS SECURITY TEST: requires unprivileged Linux and working Bubblewrap"]
fn approved_chatgpt_home_persists_without_exposing_original_credentials() {
    use agentvault::{
        policy::config::Config,
        sandbox::backend::Backend,
        security::{codex_auth, paths::Dir},
        workspace::prepare,
    };
    use std::os::unix::fs::PermissionsExt;
    let project = tempfile::tempdir().unwrap();
    let host = tempfile::tempdir().unwrap();
    let source = host.path().join("auth.json");
    let original = br#"{"auth_mode":"chatgpt","tokens":{"id_token":"fake-id","access_token":"fake-access","refresh_token":"fake-refresh","account_id":"fake-account"}}"#;
    std::fs::write(&source, original).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = Config::for_host();
    let backend = Backend::select(project.path(), &config).unwrap();
    let matcher = agentvault::policy::matcher::Matcher::new(&config).unwrap();
    let work = prepare::prepare(&Dir::open(project.path()).unwrap(), &matcher).unwrap();
    let mut env = backend.environment(&config, &[], work.path()).unwrap();
    backend.probe(project.path(), work.path(), &env).unwrap();
    codex_auth::import(&source, &work.path().parent().unwrap().join("sandbox-home")).unwrap();
    codex_auth::configure(&mut env);
    for script in [
        r#"grep -q fake-access "$CODEX_HOME/auth.json" && ! cat "$1" >/dev/null 2>&1 && printf refreshed > "$CODEX_HOME/auth.json""#,
        r#"grep -q refreshed "$CODEX_HOME/auth.json""#,
    ] {
        let output = backend
            .command(
                project.path(),
                work.path(),
                &env,
                &backend.resolve("sh").unwrap(),
                &[
                    "-c".into(),
                    script.into(),
                    "probe".into(),
                    source.to_str().unwrap().into(),
                ],
            )
            .unwrap()
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic sandbox authentication-copy check failed"
        );
    }
    assert_eq!(std::fs::read(source).unwrap(), original);
    backend.cleanup_private_dirs(work.path(), &env).unwrap();
    assert!(!work.path().parent().unwrap().join("sandbox-home").exists());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "REAL Linux Bubblewrap test: npm-style internal executable link"]
fn npm_style_link_executes_without_host_secret_access() {
    use agentvault::{
        policy::{config::Config, matcher::Matcher},
        sandbox::backend::Backend,
        security::paths::Dir,
        workspace::prepare,
    };
    use std::os::unix::fs::{symlink, PermissionsExt};
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join(".env"), "SYNTHETIC_SECRET").unwrap();
    std::fs::create_dir_all(project.path().join("node_modules/.bin")).unwrap();
    std::fs::create_dir_all(project.path().join("node_modules/demo/bin")).unwrap();
    let target = project.path().join("node_modules/demo/bin/tool");
    std::fs::write(&target, b"#!/bin/sh\n[ ! -e .env ] || exit 9\n! cat \"$1/.env\" >/dev/null 2>&1 || exit 10\nprintf edited > source.txt\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    symlink(
        "../demo/bin/tool",
        project.path().join("node_modules/.bin/tool"),
    )
    .unwrap();
    let config = Config::for_host();
    let matcher = Matcher::new(&config).unwrap();
    let work = prepare::prepare(&Dir::open(project.path()).unwrap(), &matcher).unwrap();
    let backend = Backend::select(project.path(), &config).unwrap();
    let env = backend.environment(&config, &[], work.path()).unwrap();
    backend.probe(project.path(), work.path(), &env).unwrap();
    let output = backend
        .command(
            project.path(),
            work.path(),
            &env,
            &backend.resolve("sh").unwrap(),
            &[
                "-c".into(),
                "./node_modules/.bin/tool \"$1\"".into(),
                "probe".into(),
                project.path().to_str().unwrap().into(),
            ],
        )
        .unwrap()
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        std::fs::read(work.path().join("source.txt")).unwrap(),
        b"edited"
    );
    assert!(!project.path().join("source.txt").exists());
    prepare::snapshot(&Dir::open(work.path()).unwrap(), &matcher, true).unwrap();
}
