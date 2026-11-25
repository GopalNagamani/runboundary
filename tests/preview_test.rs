//! Real preview security tests are opt-in and require a supported OS sandbox.
use runboundary::{
    policy::{config::Config, matcher::Matcher},
    security::{audit, paths::Dir},
    workspace::prepare::{self, Workspace},
};
use std::{path::Path, process::Command};
struct Session {
    root: tempfile::TempDir,
    work: Workspace,
    id: String,
}
impl Session {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut config = Config::for_host();
        if cfg!(target_os = "macos") {
            if let Some(runtime) = std::env::var_os("RUNBOUNDARY_TEST_RUNTIME_ROOT") {
                config.sandbox.runtime_roots.push(runtime.into());
            }
        }
        std::fs::write(
            root.path().join("runboundary.yaml"),
            serde_yaml::to_string(&config).unwrap(),
        )
        .unwrap();
        std::fs::write(root.path().join("source.txt"), "original").unwrap();
        std::fs::write(root.path().join(".env"), "SYNTHETIC_HOST_SECRET").unwrap();
        let matcher = Matcher::new(&config).unwrap();
        let work = prepare::prepare(&Dir::open(root.path()).unwrap(), &matcher).unwrap();
        std::fs::write(work.path().join("source.txt"), "agent edit").unwrap();
        audit::log(root.path(), "test", "synthetic retained preview session").unwrap();
        let id = runboundary::cli::review::retain(
            root.path(),
            work.path().to_owned(),
            work.baseline.clone(),
        )
        .unwrap();
        Self { root, work, id }
    }
    fn preview(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_runb"));
        command.args([
            "--project",
            self.root.path().to_str().unwrap(),
            "preview",
            &self.id,
        ]);
        command
    }
}
#[test]
fn preview_cli_requires_a_command_and_valid_port() {
    use clap::Parser;
    use runboundary::cli::{Cli, Commands};
    assert!(Cli::try_parse_from(["runb", "preview", "session"]).is_err());
    assert!(
        Cli::try_parse_from(["runb", "preview", "session", "--port", "0", "--", "sh"]).is_err()
    );
    assert!(
        Cli::try_parse_from(["runb", "preview", "session", "--port", "5173", "--", "sh"]).is_err()
    );
    assert!(Cli::try_parse_from([
        "runb",
        "preview",
        "session",
        "--allow-network-listen",
        "--port",
        "5173",
        "--",
        "npm",
        "run",
        "dev"
    ])
    .is_ok());
    let cli = Cli::try_parse_from([
        "runb", "preview", "session", "npm", "run", "dev", "--", "--port", "5173",
    ])
    .unwrap();
    let Commands::Preview {
        command,
        allow_network_listen,
        port,
        ..
    } = cli.command
    else {
        panic!("expected preview")
    };
    assert_eq!(command, ["npm", "run", "dev", "--", "--port", "5173"]);
    assert!(!allow_network_listen);
    assert!(port.is_empty());
}
#[test]
fn preview_and_apply_refuse_a_busy_session() {
    let session = Session::new();
    let root = Dir::open(session.root.path()).unwrap();
    let _lock = root
        .lock(Path::new(&format!(
            ".runboundary/session-{}.lock",
            session.id
        )))
        .unwrap();
    let result = session
        .preview()
        .args(["--", "sh", "-c", "exit 0"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("session is busy"));
    assert!(
        runboundary::cli::review::execute(session.root.path(), &session.id, true, false).is_err()
    );
    assert_eq!(
        std::fs::read(session.root.path().join("source.txt")).unwrap(),
        b"original"
    );
}
#[test]
fn preview_rejects_a_substituted_workspace_directory() {
    let session = Session::new();
    let old = session.work.path().with_file_name("old-workspace");
    std::fs::rename(session.work.path(), &old).unwrap();
    std::os::unix::fs::symlink(session.root.path(), session.work.path()).unwrap();
    let result = session
        .preview()
        .args(["--", "sh", "-c", "exit 0"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("without symlinks"));
}
#[test]
fn preview_tcp_listeners_require_explicit_opt_in_and_keep_process_deny_last() {
    for allow in [false, true] {
        let mut profile = "(version 1)\n(deny default)\n(deny process-info*)\n".to_string();
        runboundary::sandbox::seatbelt::configure_preview_network(&mut profile, allow).unwrap();
        let action = if allow { "allow" } else { "deny" };
        assert!(profile.contains(&format!(
            "({action} network-bind network-inbound (local tcp))"
        )));
        assert!(!profile.contains("localhost"));
        assert!(profile.ends_with("\n(deny process-info*)\n"));
    }
}

#[test]
#[ignore = "REAL OS SECURITY TEST: requires working Bubblewrap or macOS Seatbelt from Terminal"]
fn preview_edits_are_isolated_rescanned_and_reviewable_even_after_failure() {
    let session = Session::new();
    for script in [
        r#"set -eu
! cat .env >/dev/null 2>&1
! cat "$1/.env" >/dev/null 2>&1
[ -z "${OPENAI_API_KEY+x}" ]
[ -z "${SSH_AUTH_SOCK+x}" ]
[ ! -e "$HOME/.codex/auth.json" ]
printf 'preview edit' > source.txt
printf 'generated' > generated.txt
exit 7"#,
        "test ! -e \"$HOME/.codex/auth.json\"",
    ] {
        let output = session
            .preview()
            .env("OPENAI_API_KEY", "SYNTHETIC_NOT_APPROVED")
            .args([
                "--",
                "sh",
                "-c",
                script,
                "preview-test",
                session.root.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(if script.contains("exit 7") { 7 } else { 0 }),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(
        std::fs::read(session.root.path().join("source.txt")).unwrap(),
        b"original"
    );
    assert!(!session.root.path().join("generated.txt").exists());
    assert!(!session
        .work
        .path()
        .parent()
        .unwrap()
        .join("sandbox-home")
        .exists());
    runboundary::cli::review::execute(session.root.path(), &session.id, true, false).unwrap();
    assert_eq!(
        std::fs::read(session.root.path().join("source.txt")).unwrap(),
        b"preview edit"
    );
    assert_eq!(
        std::fs::read(session.root.path().join("generated.txt")).unwrap(),
        b"generated"
    );
}
#[test]
#[ignore = "REAL OS SECURITY TEST: requires working Bubblewrap or macOS Seatbelt from Terminal"]
fn protected_preview_output_is_rejected_and_cannot_apply() {
    let session = Session::new();
    let output = session
        .preview()
        .args(["--", "sh", "-c", "printf synthetic > .env"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsafe preview output rejected"));
    assert!(
        runboundary::cli::review::execute(session.root.path(), &session.id, true, false).is_err()
    );
    assert_eq!(
        std::fs::read(session.root.path().join(".env")).unwrap(),
        b"SYNTHETIC_HOST_SECRET"
    );
}

#[test]
#[ignore = "REAL OS SECURITY TEST: requires supported sandbox and approved Python (3.12 on macOS); opens a local test server"]
fn browser_can_reach_a_sandboxed_loopback_preview() {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        time::{Duration, Instant},
    };
    struct Server(std::process::Child);
    impl Drop for Server {
        fn drop(&mut self) {
            unsafe {
                libc::kill(self.0.id() as i32, libc::SIGTERM);
            }
            for _ in 0..100 {
                if self.0.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let session = Session::new();
    let port = TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let script = r#"import socket,sys
port=int(sys.argv[1])
server=socket.socket()
server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
server.bind(('127.0.0.1',port))
server.listen(1)
server.settimeout(10)
open('preview-ready.txt','w').write('ready')
conn,_=server.accept()
conn.recv(4096)
conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 22\r\nConnection: close\r\n\r\nRUNBOUNDARY_PREVIEW_OK')
conn.close()
server.close()
"#;
    let child = session
        .preview()
        .args([
            "--allow-network-listen",
            "--port",
            &port.to_string(),
            "--",
            // Match the real macOS security suite: /usr/bin/python3 is an
            // Xcode launcher, not the approved standalone Python runtime.
            if cfg!(target_os = "macos") {
                "python3.12"
            } else {
                "python3"
            },
            "-c",
            script,
            &port.to_string(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut server = Server(child);
    let deadline = Instant::now() + Duration::from_secs(15);
    while !session.work.path().join("preview-ready.txt").exists() {
        if let Some(status) = server.0.try_wait().unwrap() {
            let mut stderr = String::new();
            server
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("real preview server startup failed ({status}): {stderr}");
        }
        assert!(
            Instant::now() < deadline,
            "preview server readiness timed out"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut browser = TcpStream::connect(("127.0.0.1", port)).unwrap();
    browser
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    browser
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    browser.read_to_string(&mut response).unwrap();
    assert!(response.contains("RUNBOUNDARY_PREVIEW_OK"));
    loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "preview exit timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!session.root.path().join("preview-ready.txt").exists());
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "REAL OS SECURITY TEST: requires macOS Seatbelt and approved Python 3.12 from Terminal"]
fn macos_preview_without_listener_approval_refuses_tcp_binds() {
    let session = Session::new();
    let script = r#"import socket,json,sys
for family,address in [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::1'),(socket.AF_INET6,'::')]:
    sock=socket.socket(family,socket.SOCK_STREAM)
    try:
        sock.bind((address,0))
    except PermissionError as error:
        print(json.dumps({'stage':'default-bind','address':address,'denied':True,'errno':error.errno}),flush=True)
    else:
        raise RuntimeError('TCP bind succeeded without --allow-network-listen: '+address)
    finally:
        sock.close()
"#;
    let output = session
        .preview()
        .args(["--", "python3.12", "-c", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("default-bind"));
}
