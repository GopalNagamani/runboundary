//! REAL macOS process tests. Run explicitly from Terminal, not a managed sandbox.
#![cfg(target_os = "macos")]
use runboundary::{
    policy::{config::Config, matcher::Matcher},
    sandbox::{backend::Backend, process},
    security::paths::Dir,
    workspace::{
        prepare::{self, Workspace},
        sync,
    },
};
use std::{
    collections::BTreeMap,
    os::{
        fd::AsRawFd,
        unix::{fs::symlink, net::UnixListener},
    },
    path::PathBuf,
    process::{Command, Output},
};
struct Fixture {
    project: tempfile::TempDir,
    host: tempfile::TempDir,
    work: Workspace,
    backend: Backend,
    env: BTreeMap<String, String>,
    matcher: Matcher,
}
impl Fixture {
    fn new() -> Self {
        let fixture = Self::unprobed();
        fixture.backend.probe(fixture.project.path(),fixture.work.path(),&fixture.env).expect("real macOS Seatbelt preflight failed; run from your own Terminal; unsupported environments must not silently pass");
        fixture
    }
    // The policy comparison deliberately omits preflight so a broken candidate
    // produces diagnostic evidence. It never imports approved authentication.
    fn unprobed() -> Self {
        let project = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        for dir in [".ssh", ".aws"] {
            std::fs::create_dir(host.path().join(dir)).unwrap();
        }
        for (name, data) in [
            (".ssh/id_rsa", "SYNTHETIC_SSH"),
            (".aws/credentials", "SYNTHETIC_AWS"),
            ("canary", "SYNTHETIC_HOST"),
        ] {
            std::fs::write(host.path().join(name), data).unwrap();
        }
        for (name, data) in [
            (".env", "SYNTHETIC_SECRET"),
            (".env.production", "SYNTHETIC_PRODUCTION"),
            (".env.example", "TEMPLATE"),
            ("source.txt", "original"),
        ] {
            std::fs::write(project.path().join(name), data).unwrap();
        }
        let mut config = Config::for_host();
        if let Some(root) = std::env::var_os("RUNBOUNDARY_TEST_RUNTIME_ROOT") {
            config.sandbox.runtime_roots.push(PathBuf::from(root));
        }
        let backend = Backend::select(project.path(), &config).unwrap();
        let matcher = Matcher::new(&config).unwrap();
        let work = prepare::prepare(&Dir::open(project.path()).unwrap(), &matcher).unwrap();
        let env = backend.environment(&config, &[], work.path()).unwrap();
        Self {
            project,
            host,
            work,
            backend,
            env,
            matcher,
        }
    }
    fn command(&self, exe: &str, args: &[String]) -> Command {
        self.backend.command(self.project.path(),self.work.path(),&self.env,&self.backend.resolve(exe).expect("required runtime missing: approve a Homebrew tree with Python 3.12 and Node.js"),args).unwrap()
    }
    fn exec(&self, exe: &str, args: &[String]) -> Output {
        self.command(exe, args).output().unwrap()
    }
    fn shell(&self, script: &str, paths: &[PathBuf]) -> Output {
        let mut args = vec!["-c".into(), script.into(), "probe".into()];
        args.extend(paths.iter().map(|p| p.to_str().unwrap().to_owned()));
        self.exec("sh", &args)
    }
}
fn ok(output: Output) {
    assert!(
        output.status.success(),
        "status {}; stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "REAL macOS Seatbelt test: run from Terminal"]
fn direct_secrets_and_original_project_denied() {
    let f = Fixture::new();
    ok(f.shell(
        "! cat .env && ! cat .env.production && ! cat \"$1/.env\" && ! ls \"$1\"",
        &[f.project.path().to_owned()],
    ));
}
#[test]
#[ignore = "REAL macOS Seatbelt test: requires approved Python 3.12 runtime"]
fn python_secret_read_denied() {
    let f = Fixture::new();
    ok(f.exec("python3.12",&["-c".into(),"import pathlib,sys; p=pathlib.Path(sys.argv[1]);\ntry: p.read_bytes()\nexcept PermissionError: pass\nelse: raise AssertionError('host secret readable')".into(),f.project.path().join(".env").to_str().unwrap().into()]));
}
#[test]
#[ignore = "REAL macOS Seatbelt test: requires approved Node.js runtime"]
fn node_secret_read_denied() {
    let f = Fixture::new();
    ok(f.exec("node",&["-e".into(),"try {require('fs').readFileSync(process.argv[1]);process.exit(1)} catch(e) {if(e.code!=='EPERM'&&e.code!=='EACCES') throw e}".into(),f.project.path().join(".env").to_str().unwrap().into()]));
}
#[test]
#[ignore = "REAL macOS Seatbelt test: run from Terminal"]
fn allowed_template_source_and_private_directories_writable() {
    let f = Fixture::new();
    ok(f.shell("grep -q TEMPLATE .env.example && printf edited > source.txt && printf private > \"$HOME/cache\" && printf temp > \"$TMPDIR/tmp\"",&[]));
    assert_eq!(
        std::fs::read(f.work.path().join("source.txt")).unwrap(),
        b"edited"
    );
    assert_eq!(
        std::fs::read(f.project.path().join("source.txt")).unwrap(),
        b"original"
    );
    f.backend
        .cleanup_private_dirs(f.work.path(), &f.env)
        .unwrap();
    assert!(!std::path::Path::new(&f.env["HOME"]).exists());
    assert!(f.work.path().join("source.txt").exists());
}
#[test]
#[ignore = "REAL macOS Seatbelt test: run from Terminal"]
fn host_credentials_and_writes_denied() {
    let f = Fixture::new();
    ok(f.shell("! cat \"$1/.ssh/id_rsa\" && ! cat \"$1/.aws/credentials\" && ! (printf bad > \"$1/canary\")",&[f.host.path().to_owned()]));
    assert_eq!(
        std::fs::read(f.host.path().join("canary")).unwrap(),
        b"SYNTHETIC_HOST"
    );
}
#[test]
#[ignore = "REAL macOS Seatbelt test: requires approved Python 3.12 runtime"]
fn host_unix_socket_connection_denied() {
    let f = Fixture::new();
    // The only intentional host Unix-socket exception is the real OS DNS
    // daemon. Prove it exists/accepts on the host and inside the sandbox.
    drop(
        std::os::unix::net::UnixStream::connect("/private/var/run/mDNSResponder")
            .expect("macOS DNS daemon socket must be available for this security test"),
    );
    ok(f.exec("python3.12", &["-c".into(), "import socket; s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect('/private/var/run/mDNSResponder'); s.close()".into()]));
    let _socket = UnixListener::bind(f.host.path().join("docker.sock"))
        .expect("host Unix socket fixture requires an ordinary Terminal session");
    drop(std::os::unix::net::UnixStream::connect(f.host.path().join("docker.sock")).unwrap());
    ok(f.exec("python3.12",&["-c".into(),"import socket,sys; s=socket.socket(socket.AF_UNIX);\ntry: s.connect(sys.argv[1])\nexcept PermissionError: pass\nelse: raise AssertionError('host Unix socket reachable')".into(),f.host.path().join("docker.sock").to_str().unwrap().into()]));
}
#[test]
#[ignore = "REAL macOS Seatbelt test: run from Terminal"]
fn descendants_and_symlink_cannot_escape() {
    let f = Fixture::new();
    symlink(f.host.path().join("canary"), f.work.path().join("alias")).unwrap();
    ok(f.shell("sh -c '! cat alias' && ! /usr/bin/sandbox-exec -p '(version 1)(allow default)' /bin/cat \"$1\"", &[f.host.path().join("canary")]));
    assert!(prepare::snapshot(&Dir::open(f.work.path()).unwrap(), &f.matcher, true).is_err());
}
#[test]
#[ignore = "REAL macOS Seatbelt test: requires approved Python 3.12 runtime"]
fn inherited_secret_descriptor_closed() {
    let f = Fixture::new();
    let secret = std::fs::File::open(f.project.path().join(".env")).unwrap();
    let fd = unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_DUPFD, 100) };
    assert!(fd >= 100);
    let output=f.exec("python3.12",&["-c".into(),"import os,sys,errno;\ntry: os.fstat(int(sys.argv[1]))\nexcept OSError as e: assert e.errno==errno.EBADF\nelse: raise AssertionError('secret descriptor inherited')".into(),fd.to_string()]);
    unsafe { libc::close(fd) };
    ok(output);
}
#[test]
#[ignore = "REAL macOS Seatbelt test: run from Terminal"]
fn regular_file_stdio_refused() {
    let f = Fixture::new();
    let secret = std::fs::File::open(f.project.path().join(".env")).unwrap();
    let mut command = f.command("cat", &[]);
    command.stdin(secret);
    assert!(command.output().is_err());
}
#[test]
#[ignore = "REAL macOS Seatbelt test: run from Terminal"]
fn exit_status_preserved() {
    let f = Fixture::new();
    assert_eq!(process::exit_code(f.shell("exit 37", &[]).status), 37);
}
#[test]
#[ignore = "REAL macOS Seatbelt test: run from Terminal"]
fn invalid_profile_refuses_execution() {
    let f = Fixture::new();
    let marker = f.work.path().join("should-not-run");
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .env_clear()
        .args([
            "-p",
            "(invalid profile",
            "/bin/sh",
            "-c",
            "touch \"$1\"",
            "probe",
        ])
        .arg(&marker);
    process::harden(&mut command);
    assert!(!command.output().unwrap().status.success());
    assert!(!marker.exists());
}
#[test]
#[ignore = "REAL macOS Seatbelt test: run from Terminal"]
fn protected_agent_output_cannot_sync() {
    let f = Fixture::new();
    ok(f.shell("printf generated > .env", &[]));
    let output = Dir::open(f.work.path()).unwrap();
    assert!(prepare::snapshot(&output, &f.matcher, true).is_err());
    let reviewed = prepare::Snapshot::new();
    assert!(sync::apply(
        f.project.path(),
        &Dir::open(f.project.path()).unwrap(),
        &output,
        &f.work.baseline,
        &reviewed,
        &f.matcher
    )
    .is_err());
    assert_eq!(
        std::fs::read(f.project.path().join(".env")).unwrap(),
        b"SYNTHETIC_SECRET"
    );
}

#[test]
#[ignore = "REAL macOS Seatbelt test: requires approved Python 3.12 runtime"]
fn host_process_environment_cannot_be_read_through_sysctl() {
    process_data_comparison(Fixture::new(), false);
}

#[test]
#[ignore = "REAL macOS diagnostic: synthetic processes only; run from Terminal"]
fn diagnose_process_data_isolation() {
    process_data_comparison(Fixture::unprobed(), true);
}

fn process_data_comparison(f: Fixture, diagnostic: bool) {
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Stdio};
    struct Canary(Child);
    impl Drop for Canary {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let python = f.backend.resolve("python3.12").unwrap();
    // A Homebrew process, rather than an Apple restricted binary: newer macOS
    // can omit the environment of Apple binaries independently of Seatbelt.
    let mut host = Canary(
        Command::new(&python)
            .args([
                "-c",
                "import sys; print('READY', flush=True); sys.stdin.readline()",
                "SYNTHETIC_HOST_ARGUMENT=not-real",
            ])
            .env_clear()
            .env("SYNTHETIC_HOST_TOKEN", "not-real")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut ready = String::new();
    BufReader::new(host.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(ready, "READY\n", "synthetic host must finish starting");
    let args = vec![
        "-c".into(),
        include_str!("macos_process_probe.py").into(),
        host.0.id().to_string(),
    ];
    let control = Command::new(&python)
        .args(&args)
        .env_clear()
        .output()
        .unwrap();
    assert!(control.status.success(), "positive control failed");
    let control: Vec<serde_json::Value> = serde_json::from_slice(&control.stdout).unwrap();
    println!(
        "Unsandboxed synthetic control: {}",
        serde_json::json!(control)
    );
    assert!(
        control
            .iter()
            .all(|r| r["argument_visible"] == true && r["environment_visible"] == true),
        "control must retrieve both fake argument and fake environment data"
    );

    let variants = [
        ("current-profile", ""),
        ("current-profile-descendant", ""),
        ("historical-vulnerable-profile", ""),
        ("explicit-named-sysctl-deny", "\n(deny sysctl-read (sysctl-name \"kern.procargs\") (sysctl-name \"kern.procargs2\"))\n"),
        ("explicit-prefix-sysctl-deny", "\n(deny sysctl-read (sysctl-name-prefix \"kern.procargs\"))\n"),
        ("all-sysctl-deny", "\n(deny sysctl-read)\n"),
        ("all-process-info-deny", "\n(deny process-info*)\n"),
        ("sysctl-and-process-info-deny", "\n(deny sysctl-read)\n(deny process-info*)\n"),
    ];
    let mut blocked = Vec::new();
    let mut baseline_exposed = false;
    let mut production_denials = 0;
    for (name, extra) in variants {
        let production = name.starts_with("current-profile");
        if !diagnostic && !production {
            continue;
        }
        // Preserve production paths, env and hardening; vary only the SBPL rule.
        let base = if name == "current-profile-descendant" {
            let mut descendant = vec![
                "-c".into(),
                "\"$@\"".into(),
                "runboundary-synthetic-descendant".into(),
                python.to_str().unwrap().into(),
            ];
            descendant.extend(args.clone());
            f.command("sh", &descendant)
        } else {
            f.command("python3.12", &args)
        };
        let mut command = Command::new(base.get_program());
        command.env_clear().envs(&f.env).current_dir(f.work.path());
        let mut profile_next = false;
        for arg in base.get_args() {
            if profile_next {
                let mut source = arg.to_str().unwrap().to_owned();
                if !production {
                    // Reconstruct the old unsafe policy only in this synthetic
                    // diagnostic, so candidate comparisons remain meaningful.
                    source = source.replace(
                        "(deny process-info*)",
                        "(allow process-info* (target self))",
                    );
                }
                command.arg(format!("{source}{extra}"));
                profile_next = false;
            } else {
                command.arg(arg);
                profile_next = arg == "-p";
            }
        }
        process::harden(&mut command);
        let output = command.output().unwrap();
        if !output.status.success() {
            println!("{name}: payload did not complete ({}); this does NOT count as a denied process-data read", output.status);
            // This fixture imports no authentication and runs only our fixed
            // synthetic payload. Bound and escape stderr without reaching into
            // the production backend's private diagnostic implementation.
            let diagnostic: String = String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(4096)
                .collect();
            println!("{name} startup diagnostic: {diagnostic:?}");
            continue;
        }
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
            .expect("completed probe must return structured, nonsecret results");
        println!("{name}: {}", serde_json::json!(rows));
        let denies_reads = rows.iter().all(|r| r["denied"] == true);
        if production {
            production_denials += usize::from(denies_reads);
        } else if name == "historical-vulnerable-profile" {
            baseline_exposed = rows
                .iter()
                .any(|r| r["argument_visible"] == true || r["environment_visible"] == true);
        } else if denies_reads {
            blocked.push(name);
        }
    }
    assert!(
        production_denials == 2,
        "production profile must deny both actual process-data reads directly and in a descendant"
    );
    if !diagnostic {
        return;
    }
    println!("Rules that actually denied both process-data reads: {blocked:?}");
    assert!(
        baseline_exposed,
        "must reproduce the baseline leak, rather than count an unsupported runtime as success"
    );
    assert!(
        !blocked.is_empty(),
        "no candidate has demonstrated process-data isolation"
    );
}

#[test]
#[ignore = "REAL macOS Seatbelt test: requires approved Python 3.12 runtime"]
fn outbound_ip_networking_allowed() {
    let f = Fixture::new();
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("host TCP fixture requires an ordinary Terminal session");
    ok(f.exec("python3.12",&["-c".into(),"import socket,sys; s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=3);s.close()".into(),listener.local_addr().unwrap().port().to_string()]));
}

#[test]
#[ignore = "REAL macOS Seatbelt test: requires approved Node.js runtime"]
fn node_shell_pipeline_starts_with_process_data_denied() {
    let f = Fixture::new();
    let output = f.exec(
        "node",
        &[
            "-e".into(),
            r#"const r=require('child_process').spawnSync('/bin/sh',['-c',`printf '%s\n' synthetic-input | /bin/sh -c 'read value; test "$value" = synthetic-input || exit 3; printf SHELL_PIPELINE_OK'`],{encoding:'utf8'}); if(r.status!==0){console.error('shell subprocess failed',r.status,r.error,r.stderr);process.exit(1)} if(r.stdout!=='SHELL_PIPELINE_OK')process.exit(2);"#.into(),
        ],
    );
    ok(output);
}

#[test]
#[ignore = "REAL macOS Seatbelt test: requires approved Python 3.12 runtime"]
fn absent_system_codex_policy_is_not_permission_denied() {
    let f = Fixture::new();
    for name in ["requirements.toml", "managed_config.toml", "config.toml"] {
        let path = PathBuf::from("/private/etc/codex").join(name);
        if path.try_exists().unwrap() {
            println!("Existing administrator policy {name}: verifying open/close only; absence assertion is inapplicable");
            // Do not read a real administrator policy into test output.
            ok(f.exec(
                "python3.12",
                &[
                    "-c".into(),
                    "import pathlib,sys; pathlib.Path(sys.argv[1]).open('rb').close()".into(),
                    path.to_str().unwrap().into(),
                ],
            ));
            continue;
        }
        ok(f.exec("python3.12", &["-c".into(), "import pathlib,sys; p=pathlib.Path(sys.argv[1]);\ntry: p.read_bytes()\nexcept FileNotFoundError: pass\nelse: raise AssertionError('absent policy unexpectedly present')".into(), PathBuf::from("/etc/codex").join(name).to_str().unwrap().into()]));
    }
}

#[test]
#[ignore = "REAL macOS Seatbelt test: requires approved Node.js runtime"]
fn resolver_aliases_and_openssl_configuration_readable() {
    let f = Fixture::new();
    ok(f.exec("node", &["-e".into(), "const fs=require('fs');for(const p of ['/etc/resolv.conf','/private/etc/resolv.conf','/private/var/run/resolv.conf','/private/etc/ssl/openssl.cnf']){const fd=fs.openSync(p,'r');fs.closeSync(fd);}for(const p of ['/etc/resolv.conf','/private/etc/resolv.conf'])fs.readlinkSync(p);".into()]));
}

#[test]
#[ignore = "REAL macOS Seatbelt test: requires approved Python 3.12 runtime"]
fn public_ca_bundle_loads_with_tls_verification_enabled() {
    let f = Fixture::new();
    assert_eq!(f.env["SSL_CERT_FILE"], "/private/etc/ssl/cert.pem");
    assert_eq!(f.env["CODEX_CA_CERTIFICATE"], f.env["SSL_CERT_FILE"]);
    ok(f.exec("python3.12", &["-c".into(), "import ssl; c=ssl.create_default_context(); assert c.verify_mode==ssl.CERT_REQUIRED; assert c.check_hostname; assert c.cert_store_stats()['x509_ca']>0, 'public root certificates were not loaded'".into()]));
}

#[test]
#[ignore = "requires real macOS Seatbelt; synthetic credentials only"]
fn approved_chatgpt_copy_is_private_and_host_auth_is_inaccessible() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::new();
    let source = f.host.path().canonicalize().unwrap().join("auth.json");
    let bytes = br#"{"auth_mode":"chatgpt","tokens":{"id_token":"fake-id","access_token":"fake-access","refresh_token":"fake-refresh","account_id":"fake-account"},"unrelated":"must-not-import"}"#;
    std::fs::write(&source, bytes).unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
    runboundary::security::codex_auth::import(&source, std::path::Path::new(&f.env["HOME"]))
        .unwrap();
    runboundary::security::codex_auth::configure(&mut f.env);
    ok(f.shell(
        r#"set -eu
[ -f "$CODEX_HOME/auth.json" ]
grep -q fake-access "$CODEX_HOME/auth.json"
! grep -q must-not-import "$CODEX_HOME/auth.json"
! cat "$1" >/dev/null 2>&1
! cat "$2" >/dev/null 2>&1
printf refreshed > "$CODEX_HOME/auth.json"
"#,
        &[source.clone(), f.host.path().join(".ssh/id_rsa")],
    ));
    assert_eq!(std::fs::read(&source).unwrap(), bytes);
    f.backend
        .cleanup_private_dirs(f.work.path(), &f.env)
        .unwrap();
    assert!(!std::path::Path::new(&f.env["HOME"]).exists());
}

#[test]
#[ignore = "REAL macOS Seatbelt test: npm-style internal executable link; run from Terminal"]
fn npm_style_link_executes_inside_sandbox_without_host_secret_access() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::unprobed();
    std::fs::create_dir_all(f.project.path().join("node_modules/.bin")).unwrap();
    std::fs::create_dir_all(f.project.path().join("node_modules/demo/bin")).unwrap();
    let target = f.project.path().join("node_modules/demo/bin/tool");
    std::fs::write(&target, b"#!/bin/sh\n[ ! -e .env ] || exit 9\n! cat \"$1/.env\" >/dev/null 2>&1 || exit 10\nprintf 'edited via dependency link' > source.txt\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    symlink(
        "../demo/bin/tool",
        f.project.path().join("node_modules/.bin/tool"),
    )
    .unwrap();
    let work = prepare::prepare(&Dir::open(f.project.path()).unwrap(), &f.matcher).unwrap();
    let env = f
        .backend
        .environment(&Config::for_host(), &[], work.path())
        .unwrap();
    f.backend
        .probe(f.project.path(), work.path(), &env)
        .unwrap();
    let output = f
        .backend
        .command(
            f.project.path(),
            work.path(),
            &env,
            &f.backend.resolve("sh").unwrap(),
            &[
                "-c".into(),
                "./node_modules/.bin/tool \"$1\"".into(),
                "probe".into(),
                f.project.path().to_str().unwrap().into(),
            ],
        )
        .unwrap()
        .output()
        .unwrap();
    ok(output);
    let after = prepare::snapshot(&Dir::open(work.path()).unwrap(), &f.matcher, true).unwrap();
    assert_eq!(
        std::fs::read(work.path().join("source.txt")).unwrap(),
        b"edited via dependency link"
    );
    assert_eq!(
        std::fs::read(f.project.path().join("source.txt")).unwrap(),
        b"original"
    );
    assert!(after[std::path::Path::new("node_modules/.bin/tool")]
        .link_target
        .is_some());
}
