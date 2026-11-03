//! Project metadata tests; these do not certify sandbox or Simulator confinement.
use agentvault::{
    cli::review,
    policy::{config::Config, matcher::Matcher},
    security::{audit, paths::Dir},
    workspace::{prepare, xcode},
};
use std::{
    path::{Path, PathBuf},
    process::Command,
};
const PROJECT: &str = include_str!("fixtures/navigator.pbxproj");
fn register(text: &str, files: &[&str]) -> anyhow::Result<(String, usize)> {
    xcode::register(
        text,
        Path::new("App.xcodeproj"),
        &files.iter().map(PathBuf::from).collect::<Vec<_>>(),
    )
}
#[test]
fn navigator_insertion_is_idempotent_and_preserves_build_phases() {
    let (updated, count) = register(
        PROJECT,
        &[
            "output.txt",
            "Sources/New.swift",
            "Sources/Existing.swift",
            "en.lproj/Localizable.strings",
            "App.xcdatamodeld/App.xcdatamodel",
            "output.txt",
        ],
    )
    .unwrap();
    assert_eq!(count, 2);
    assert!(updated.contains("PHASE = {isa = PBXSourcesBuildPhase; files = (BUILD,); };"));
    assert!(updated.contains("/* End PBXProject section */"));
    assert!(updated.contains("path = \"Sources/New.swift\"; sourceTree = SOURCE_ROOT"));
    assert_eq!(
        register(&updated, &["output.txt", "Sources/New.swift"]).unwrap(),
        (updated, 0)
    );
}
#[test]
fn quotes_comments_and_arrays_without_trailing_commas() {
    let input = PROJECT.replace(
        "(SOURCES, LOCALIZED, MODEL, PRODUCT)",
        "(SOURCES, LOCALIZED, MODEL, PRODUCT /* last */)",
    );
    let (updated, _) = register(&input, &["a \"quoted\" name.txt", "safe/*comment*/.txt"]).unwrap();
    assert!(updated.contains("path = \"a \\\"quoted\\\" name.txt\""));
    assert_eq!(
        register(&updated, &["a \"quoted\" name.txt", "safe/*comment*/.txt"])
            .unwrap()
            .1,
        0
    );
}
#[test]
fn malformed_unsupported_and_traversal_projects_are_refused() {
    for bad in [
        PROJECT.replace(
            "archiveVersion = 1;",
            "archiveVersion = 1; archiveVersion = 2;",
        ),
        PROJECT.replace("children = (EXISTING,)", "children = (MAIN,)"),
        PROJECT.replace("isa = PBXGroup", "isa = PBXFileSystemSynchronizedRootGroup"),
        PROJECT.replace("projectDirPath = \"\"", "projectDirPath = ../outside"),
        format!("{PROJECT} garbage"),
        "{ /* unfinished".into(),
        "{".repeat(150),
    ] {
        assert!(register(&bad, &["output.txt"]).is_err());
    }
    for path in ["../escape.txt", "/tmp/escape.txt", "bad\n.txt", ""] {
        assert!(register(PROJECT, &[path]).is_err(), "{path:?}");
    }
    assert!(xcode::register(
        PROJECT,
        Path::new("nested/App.xcodeproj"),
        &[PathBuf::from("outside.txt")]
    )
    .is_err());
}
fn cli(root: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agentvault"))
        .arg("--project")
        .arg(root)
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn retained_registration_review_and_apply_keep_host_unchanged_until_approval() {
    let root = tempfile::tempdir().unwrap();
    assert!(cli(root.path(), &["init"]).status.success());
    std::fs::create_dir(root.path().join("App.xcodeproj")).unwrap();
    std::fs::write(root.path().join("App.xcodeproj/project.pbxproj"), PROJECT).unwrap();
    let matcher = Matcher::new(&Config::load(root.path()).unwrap()).unwrap();
    let source = Dir::open(root.path()).unwrap();
    let work = prepare::prepare(&source, &matcher).unwrap();
    std::fs::write(work.path().join("output.txt"), "hello").unwrap();
    audit::log(root.path(), "test", "synthetic fixture").unwrap();
    let workspace = work.path().to_path_buf();
    let baseline = work.baseline.clone();
    let _kept = work.temp.keep();
    let id = review::retain(root.path(), workspace.clone(), baseline).unwrap();
    let output = cli(
        root.path(),
        &[
            "xcode-register",
            &id,
            "--xcode-project",
            "App.xcodeproj",
            "--new-files",
        ],
    );
    assert!(output.status.success(), "{:?}", output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("Registered 1 file"));
    assert_eq!(
        std::fs::read_to_string(root.path().join("App.xcodeproj/project.pbxproj")).unwrap(),
        PROJECT
    );
    assert!(!root.path().join("output.txt").exists());
    let registered = std::fs::read(workspace.join("App.xcodeproj/project.pbxproj")).unwrap();
    let again = cli(
        root.path(),
        &[
            "xcode-register",
            &id,
            "--xcode-project",
            "App.xcodeproj",
            "--",
            "output.txt",
        ],
    );
    assert!(again.status.success(), "{again:?}");
    assert_eq!(
        std::fs::read(workspace.join("App.xcodeproj/project.pbxproj")).unwrap(),
        registered
    );
    // No partial metadata changes on a batch containing an unsafe path.
    let denied = cli(
        root.path(),
        &[
            "xcode-register",
            &id,
            "--xcode-project",
            "App.xcodeproj",
            "--",
            "output.txt",
            "../escape",
        ],
    );
    assert!(!denied.status.success());
    assert_eq!(
        std::fs::read(workspace.join("App.xcodeproj/project.pbxproj")).unwrap(),
        registered
    );
    for name in [".env", "link.txt", "hard.txt"] {
        let path = workspace.join(name);
        match name {
            "link.txt" => std::os::unix::fs::symlink("output.txt", &path).unwrap(),
            "hard.txt" => std::fs::hard_link(workspace.join("output.txt"), &path).unwrap(),
            _ => std::fs::write(&path, "synthetic secret").unwrap(),
        }
        assert!(!cli(
            root.path(),
            &[
                "xcode-register",
                &id,
                "--xcode-project",
                "App.xcodeproj",
                "--",
                name
            ]
        )
        .status
        .success());
        std::fs::remove_file(path).unwrap();
    }
    assert!(cli(root.path(), &["review", &id, "--diff"])
        .status
        .success());
    let applied = cli(root.path(), &["review", &id, "--apply"]);
    assert!(applied.status.success(), "{applied:?}");
    assert_eq!(
        std::fs::read(root.path().join("App.xcodeproj/project.pbxproj")).unwrap(),
        registered
    );
    assert_eq!(
        std::fs::read(root.path().join("output.txt")).unwrap(),
        b"hello"
    );
    std::fs::remove_dir_all(workspace.parent().unwrap()).unwrap();
}
#[cfg(target_os = "macos")]
#[test]
fn apple_plutil_accepts_registered_openstep_project() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("project.pbxproj");
    std::fs::write(&path, register(PROJECT, &["output.txt"]).unwrap().0).unwrap();
    let output = Command::new("/usr/bin/plutil")
        .arg("-lint")
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires an explicitly selected existing project.pbxproj; reads metadata only, writes a temporary copy"]
fn existing_project_metadata_copy() {
    let selected = std::env::var_os("AGENTVAULT_TEST_XCODE_PROJECT_FILE")
        .expect("set AGENTVAULT_TEST_XCODE_PROJECT_FILE to the selected project.pbxproj");
    let text = std::fs::read_to_string(selected).unwrap();
    let (updated, count) = register(&text, &["agentvault-synthetic-navigator-check.txt"]).unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        register(&updated, &["agentvault-synthetic-navigator-check.txt"])
            .unwrap()
            .1,
        0
    );
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("project.pbxproj");
    std::fs::write(&path, updated).unwrap();
    let output = Command::new("/usr/bin/plutil")
        .arg("-lint")
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn missing_or_applied_session_reports_the_missing_record_without_recreating_it() {
    let root = tempfile::tempdir().unwrap();
    assert!(cli(root.path(), &["init"]).status.success());
    audit::log(root.path(), "test", "synthetic fixture").unwrap();
    let result = cli(
        root.path(),
        &[
            "xcode-register",
            "old-session",
            "--xcode-project",
            "App.xcodeproj",
            "--",
            "output.txt",
        ],
    );
    assert!(!result.status.success());
    let error = String::from_utf8_lossy(&result.stderr);
    assert!(
        error.contains("cannot load pending session \"old-session\""),
        "{error}"
    );
    assert!(
        error.contains("an applied session has no pending review record"),
        "{error}"
    );
    assert!(
        error.contains(".agentvault/review-old-session.json"),
        "{error}"
    );
    assert!(!root
        .path()
        .join(".agentvault/review-old-session.json")
        .exists());
}
