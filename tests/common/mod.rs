#![allow(dead_code)]
use runboundary::{
    policy::{config::Config, matcher::Matcher},
    sandbox::{bubblewrap, mounts},
    security::{environment, paths::Dir},
    workspace::prepare::{self, Workspace},
};
use std::{path::Path, process::Output};
pub struct Fixture {
    pub project: tempfile::TempDir,
    pub host_canaries: tempfile::TempDir,
    _socket: std::os::unix::net::UnixListener,
    pub work: Workspace,
    pub matcher: Matcher,
}
impl Fixture {
    pub fn new() -> Self {
        runboundary::platform::linux::require().expect("security tests require unprivileged Linux; they must not silently pass unsupported hosts");
        let host_canaries = tempfile::tempdir().unwrap();
        for dir in [".ssh", ".aws"] {
            std::fs::create_dir(host_canaries.path().join(dir)).unwrap();
        }
        std::fs::write(
            host_canaries.path().join(".ssh/id_rsa"),
            "SYNTHETIC_SSH_KEY",
        )
        .unwrap();
        std::fs::write(
            host_canaries.path().join(".aws/credentials"),
            "SYNTHETIC_AWS_KEY",
        )
        .unwrap();
        let socket =
            std::os::unix::net::UnixListener::bind(host_canaries.path().join("docker.sock"))
                .unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join(".env"), "FAKE_SECRET=not-a-real-token").unwrap();
        std::fs::write(
            project.path().join(".env.production"),
            "FAKE_PRODUCTION=not-real",
        )
        .unwrap();
        std::fs::write(project.path().join(".env.example"), "EXAMPLE=template").unwrap();
        std::fs::write(project.path().join("source.txt"), "original\n").unwrap();
        let matcher = Matcher::new(&Config::defaults()).unwrap();
        let work = prepare::prepare(&Dir::open(project.path()).unwrap(), &matcher).unwrap();
        let f = Self {
            project,
            host_canaries,
            _socket: socket,
            work,
            matcher,
        };
        bubblewrap::probe(
            f.project.path(),
            f.work.path(),
            &environment::build(&Config::defaults(), &[]).unwrap(),
        )
        .expect("real Bubblewrap startup/isolation preflight failed");
        f
    }
    pub fn exec(&self, exe: &str, args: &[&str]) -> Output {
        let exe = mounts::resolve(exe).expect(
            "required test runtime missing; install it or explicitly skip this ignored test",
        );
        let args = args.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        bubblewrap::command(
            self.project.path(),
            self.work.path(),
            &environment::build(&Config::defaults(), &[]).unwrap(),
            &exe,
            &args,
        )
        .unwrap()
        .output()
        .unwrap()
    }
    pub fn shell(&self, script: &str) -> Output {
        self.exec("sh", &["-c", script])
    }
}
pub fn successful(output: Output) {
    assert!(
        output.status.success(),
        "sandbox assertion failed; status {}, stderr {:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}
pub fn path(p: &str) -> &Path {
    Path::new(p)
}
