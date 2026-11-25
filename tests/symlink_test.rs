use runboundary::{
    policy::{config::Config, matcher::Matcher},
    security::paths::Dir,
    workspace::prepare,
};
use std::os::unix::fs::symlink;
#[test]
fn symlink_and_hardlink_copy_rejected() {
    let p = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    std::fs::write(external.path().join("secret"), "fake").unwrap();
    symlink(external.path().join("secret"), p.path().join("escape")).unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let d = Dir::open(p.path()).unwrap();
    assert!(prepare::prepare(&d, &m).is_err());
    std::fs::remove_file(p.path().join("escape")).unwrap();
    std::fs::hard_link(external.path().join("secret"), p.path().join("alias")).unwrap();
    assert!(prepare::prepare(&d, &m).is_err());
}
#[test]
fn symlink_parent_and_path_traversal_rejected() {
    let p = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), p.path().join("alias")).unwrap();
    let d = Dir::open(p.path()).unwrap();
    assert!(d
        .create(std::path::Path::new("alias/write"), b"bad", 0o600)
        .is_err());
    assert!(d.read_file("../secret", 100).is_err());
    assert!(!outside.path().join("write").exists());
}
mod common;
#[test]
#[ignore = "REAL OS SECURITY TEST: requires unprivileged Linux and working Bubblewrap"]
fn sandbox_created_symlink_cannot_reach_host() {
    let f = common::Fixture::new();
    let target = f.project.path().join(".env");
    common::successful(f.exec(
        "sh",
        &[
            "-c",
            "ln -s \"$1\" alias; ! cat alias",
            "probe",
            target.to_str().unwrap(),
        ],
    ));
    assert!(prepare::snapshot(&Dir::open(f.work.path()).unwrap(), &f.matcher, true).is_err());
}

#[test]
fn special_files_rejected_without_opening_and_private_parent_retained() {
    use std::os::unix::fs::PermissionsExt;
    let p = tempfile::tempdir().unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let d = Dir::open(p.path()).unwrap();
    let work = prepare::prepare(&d, &m).unwrap();
    std::fs::set_permissions(work.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(
        std::fs::metadata(work.path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let fifo =
        std::ffi::CString::new(p.path().join("pipe").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(prepare::prepare(&d, &m).is_err());
}

#[test]
fn npm_bin_link_is_recreated_without_following_and_tracks_target_edits() {
    use std::os::unix::fs::PermissionsExt;
    let p = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(p.path().join("node_modules/.bin")).unwrap();
    std::fs::create_dir_all(p.path().join("node_modules/acorn/bin")).unwrap();
    let target = p.path().join("node_modules/acorn/bin/acorn");
    std::fs::write(&target, "#!/bin/sh\nprintf safe\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    symlink(
        "../acorn/bin/acorn",
        p.path().join("node_modules/.bin/acorn"),
    )
    .unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let root = Dir::open(p.path()).unwrap();
    let work = prepare::prepare(&root, &m).unwrap();
    let link = work.path().join("node_modules/.bin/acorn");
    assert!(std::fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        std::path::Path::new("../acorn/bin/acorn")
    );
    assert_eq!(std::fs::read(&link).unwrap(), b"#!/bin/sh\nprintf safe\n");
    std::fs::write(work.path().join("node_modules/acorn/bin/acorn"), "edited").unwrap();
    let out = Dir::open(work.path()).unwrap();
    let after = prepare::snapshot(&out, &m, true).unwrap();
    runboundary::workspace::sync::apply(p.path(), &root, &out, &work.baseline, &after, &m).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"edited");
    assert_eq!(
        std::fs::read_link(p.path().join("node_modules/.bin/acorn")).unwrap(),
        std::path::Path::new("../acorn/bin/acorn")
    );
}

#[test]
fn symlink_escape_secret_chain_directory_and_complex_targets_are_rejected() {
    for target in [
        "../outside",
        "/etc/passwd",
        ".env",
        "protected/file",
        "directory",
        "chain",
        "missing/../safe",
    ] {
        let p = tempfile::tempdir().unwrap();
        std::fs::write(p.path().join("safe"), "permitted").unwrap();
        std::fs::write(p.path().join(".env"), "SYNTHETIC_SECRET").unwrap();
        std::fs::create_dir(p.path().join("directory")).unwrap();
        std::fs::create_dir(p.path().join("protected")).unwrap();
        std::fs::write(p.path().join("protected/file"), "SYNTHETIC_CUSTOM_SECRET").unwrap();
        symlink("safe", p.path().join("chain")).unwrap();
        symlink(target, p.path().join("alias")).unwrap();
        let mut config = Config::defaults();
        config.filesystem.protected.push("protected/**".into());
        let m = Matcher::new(&config).unwrap();
        assert!(
            prepare::prepare(&Dir::open(p.path()).unwrap(), &m).is_err(),
            "{target}"
        );
    }
}

#[test]
fn symlink_add_modify_delete_and_rollback_are_safe() {
    let p = tempfile::tempdir().unwrap();
    for name in ["a", "b"] {
        std::fs::write(p.path().join(name), name).unwrap();
    }
    symlink("a", p.path().join("link")).unwrap();
    symlink("a", p.path().join("deleted")).unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let root = Dir::open(p.path()).unwrap();
    let work = prepare::prepare(&root, &m).unwrap();
    std::fs::remove_file(work.path().join("link")).unwrap();
    symlink("b", work.path().join("link")).unwrap();
    std::fs::remove_file(work.path().join("deleted")).unwrap();
    symlink("a", work.path().join("added")).unwrap();
    let out = Dir::open(work.path()).unwrap();
    let after = prepare::snapshot(&out, &m, true).unwrap();
    runboundary::workspace::sync::apply(p.path(), &root, &out, &work.baseline, &after, &m).unwrap();
    assert_eq!(
        std::fs::read_link(p.path().join("link")).unwrap(),
        std::path::Path::new("b")
    );
    assert_eq!(
        std::fs::read_link(p.path().join("added")).unwrap(),
        std::path::Path::new("a")
    );
    assert!(std::fs::symlink_metadata(p.path().join("deleted")).is_err());

    // Force a later commit conflict after a safe link replacement was installed.
    let p = tempfile::tempdir().unwrap();
    std::fs::write(p.path().join("source"), "safe").unwrap();
    symlink("source", p.path().join("a-link")).unwrap();
    std::fs::create_dir(p.path().join("z-conflict")).unwrap();
    let root = Dir::open(p.path()).unwrap();
    let work = prepare::prepare(&root, &m).unwrap();
    std::fs::remove_file(work.path().join("a-link")).unwrap();
    std::fs::write(work.path().join("a-link"), "replacement").unwrap();
    std::fs::remove_dir(work.path().join("z-conflict")).unwrap();
    std::fs::write(work.path().join("z-conflict"), "blocked").unwrap();
    let out = Dir::open(work.path()).unwrap();
    let after = prepare::snapshot(&out, &m, true).unwrap();
    assert!(
        runboundary::workspace::sync::apply(p.path(), &root, &out, &work.baseline, &after, &m)
            .is_err()
    );
    assert_eq!(
        std::fs::read_link(p.path().join("a-link")).unwrap(),
        std::path::Path::new("source")
    );
    assert_eq!(std::fs::read(p.path().join("source")).unwrap(), b"safe");
}

#[test]
fn sandbox_link_retargeted_to_secret_or_outside_is_rejected_before_apply() {
    let p = tempfile::tempdir().unwrap();
    std::fs::write(p.path().join("source"), "safe").unwrap();
    std::fs::write(p.path().join(".env"), "SYNTHETIC_SECRET").unwrap();
    symlink("source", p.path().join("link")).unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let root = Dir::open(p.path()).unwrap();
    let work = prepare::prepare(&root, &m).unwrap();
    let out = Dir::open(work.path()).unwrap();
    for target in [".env", "../escape", "/etc/passwd"] {
        std::fs::remove_file(work.path().join("link")).unwrap();
        symlink(target, work.path().join("link")).unwrap();
        assert!(prepare::snapshot(&out, &m, true).is_err());
        assert_eq!(
            std::fs::read_link(p.path().join("link")).unwrap(),
            std::path::Path::new("source")
        );
    }
}

#[test]
fn reviewed_link_targets_are_displayed_without_reading_target_contents() {
    let p = tempfile::tempdir().unwrap();
    std::fs::write(
        p.path().join("runboundary.yaml"),
        runboundary::policy::config::DEFAULT,
    )
    .unwrap();
    std::fs::write(
        p.path().join("target"),
        "PERMITTED_CONTENT_NOT_PART_OF_THIS_DIFF",
    )
    .unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let work = prepare::prepare(&Dir::open(p.path()).unwrap(), &m).unwrap();
    symlink("target", work.path().join("alias")).unwrap();
    runboundary::security::audit::log(p.path(), "test", "synthetic link review").unwrap();
    let id =
        runboundary::cli::review::retain(p.path(), work.path().to_owned(), work.baseline.clone())
            .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_runb"))
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
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("symlink ->"));
    assert!(!text.contains("PERMITTED_CONTENT_NOT_PART_OF_THIS_DIFF"));
}

#[test]
fn staged_symlink_is_removed_safely_when_a_later_commit_fails() {
    let p = tempfile::tempdir().unwrap();
    std::fs::write(p.path().join("a-link"), "original regular file").unwrap();
    std::fs::write(p.path().join("target"), "safe").unwrap();
    std::fs::create_dir(p.path().join("z-conflict")).unwrap();
    let m = Matcher::new(&Config::defaults()).unwrap();
    let root = Dir::open(p.path()).unwrap();
    let work = prepare::prepare(&root, &m).unwrap();
    std::fs::remove_file(work.path().join("a-link")).unwrap();
    symlink("target", work.path().join("a-link")).unwrap();
    std::fs::remove_dir(work.path().join("z-conflict")).unwrap();
    std::fs::write(work.path().join("z-conflict"), "blocked").unwrap();
    let out = Dir::open(work.path()).unwrap();
    let after = prepare::snapshot(&out, &m, true).unwrap();
    assert!(
        runboundary::workspace::sync::apply(p.path(), &root, &out, &work.baseline, &after, &m)
            .is_err()
    );
    assert!(std::fs::symlink_metadata(p.path().join("a-link"))
        .unwrap()
        .is_file());
    assert_eq!(
        std::fs::read(p.path().join("a-link")).unwrap(),
        b"original regular file"
    );
    assert_eq!(std::fs::read(p.path().join("target")).unwrap(), b"safe");
}
