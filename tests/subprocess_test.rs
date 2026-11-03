mod common;
use common::*;
#[test]
#[ignore = "REAL OS SECURITY TEST: requires unprivileged Linux and working Bubblewrap"]
fn descendants_inherit_filesystem_restrictions() {
    let f = Fixture::new();
    successful(f.shell("sh -c 'sh -c \"! cat /workspace/.env\"'"));
}
#[test]
#[ignore = "REAL OS SECURITY TEST: requires unprivileged Linux and working Bubblewrap"]
fn exit_codes_preserved() {
    let f = Fixture::new();
    assert_eq!(f.shell("exit 37").status.code(), Some(37));
}

#[test]
#[ignore = "REAL OS SECURITY TEST: requires unprivileged Linux and working Bubblewrap"]
fn startup_failure_refuses_execution() {
    use agentvault::{
        policy::config::Config,
        sandbox::{bubblewrap, mounts},
        security::environment,
    };
    let f = Fixture::new();
    let marker = f.project.path().join("must-not-exist");
    let shell = mounts::resolve("sh").unwrap();
    let args = vec![
        "-c".into(),
        "touch \"$1\"".into(),
        "probe".into(),
        marker.to_str().unwrap().into(),
    ];
    let result = bubblewrap::command(
        f.project.path(),
        &f.work.path().join("missing-workspace"),
        &environment::build(&Config::defaults(), &[]).unwrap(),
        &shell,
        &args,
    )
    .unwrap()
    .output()
    .unwrap();
    assert!(!result.status.success());
    assert!(!marker.exists());
}

#[test]
#[ignore = "REAL OS SECURITY TEST: requires unprivileged Linux and working Bubblewrap"]
fn privileged_inherited_descriptor_closed() {
    use agentvault::{
        policy::config::Config,
        sandbox::{bubblewrap, mounts},
        security::environment,
    };
    use std::os::fd::AsRawFd;
    let f = Fixture::new();
    let secret = std::fs::File::open(f.project.path().join(".env")).unwrap();
    let fd = unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_DUPFD, 100) };
    assert!(fd >= 100);
    let args = vec!["-c".into(), format!("test ! -e /proc/self/fd/{fd}")];
    let result = bubblewrap::command(
        f.project.path(),
        f.work.path(),
        &environment::build(&Config::defaults(), &[]).unwrap(),
        &mounts::resolve("sh").unwrap(),
        &args,
    )
    .unwrap()
    .output()
    .unwrap();
    unsafe { libc::close(fd) };
    successful(result);
}

#[test]
#[ignore = "REAL OS SECURITY TEST: requires unprivileged Linux and working Bubblewrap"]
fn regular_file_stdio_is_refused() {
    use agentvault::{
        policy::config::Config,
        sandbox::{bubblewrap, mounts},
        security::environment,
    };
    let f = Fixture::new();
    let input = std::fs::File::open(f.project.path().join(".env")).unwrap();
    let mut command = bubblewrap::command(
        f.project.path(),
        f.work.path(),
        &environment::build(&Config::defaults(), &[]).unwrap(),
        &mounts::resolve("cat").unwrap(),
        &[],
    )
    .unwrap();
    command.stdin(input);
    assert!(
        command.output().is_err(),
        "pre-exec must reject host regular-file stdin before any agent starts"
    );
}
