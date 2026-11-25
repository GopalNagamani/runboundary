use runboundary::{
    interface_builder::{validate_relative, Artifact, Request, INPUT_LIMIT},
    policy::{config::Config, matcher::Matcher},
    security::paths::Dir,
};
use std::{os::unix::fs::symlink, path::Path};
const XIB: &[u8] = include_bytes!("fixtures/interface_builder.xib");
fn request() -> Request {
    Request {
        source: XIB.to_vec(),
        module: Some("App_Module".into()),
        deployment_target: "17.2".into(),
    }
}

#[test]
fn compiler_request_rejects_argument_injection_entities_and_oversized_input() {
    assert!(request().validate().is_ok());
    for source in [
        b"<!DOCTYPE view SYSTEM 'file:///host/secret'>".to_vec(),
        b"<!ENTITY secret SYSTEM 'file:///host/secret'>".to_vec(),
        vec![0],
        vec![255],
        vec![],
        vec![b'x'; INPUT_LIMIT as usize + 1],
    ] {
        let mut r = request();
        r.source = source;
        assert!(r.validate().is_err());
    }
    for value in [
        "--plugin",
        "App --plugin evil",
        "../App",
        "9App",
        "App;exec",
        "",
    ] {
        let mut r = request();
        r.module = Some(value.into());
        assert!(r.validate().is_err());
    }
    for value in [
        "17.2 --plugin evil",
        "--help",
        "17",
        "17..2",
        "17.256",
        "17.2.0.1",
        "",
    ] {
        let mut r = request();
        r.deployment_target = value.into();
        assert!(r.validate().is_err());
    }
}

#[test]
fn input_and_output_paths_cannot_escape_or_select_other_resource_types() {
    assert!(validate_relative(Path::new("Views/My View.xib"), "xib").is_ok());
    for value in [
        "../View.xib",
        "/host/View.xib",
        "Views/../../View.xib",
        "",
        "View.storyboard",
    ] {
        assert!(validate_relative(Path::new(value), "xib").is_err());
    }
}

#[test]
fn immutable_artifact_export_and_publication_do_not_clobber_or_follow_links() {
    let compiler = tempfile::tempdir().unwrap();
    let nib = compiler.path().join("Compiled.nib");
    std::fs::create_dir(&nib).unwrap();
    std::fs::write(nib.join("objects.nib"), b"validated bytes").unwrap();
    let artifact = Artifact::read(&Dir::open(compiler.path()).unwrap()).unwrap();
    std::fs::write(nib.join("objects.nib"), b"later compiler write").unwrap();
    let session = tempfile::tempdir().unwrap();
    let workspace = session.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let matcher = Matcher::new(&Config::for_host()).unwrap();
    artifact
        .publish(&workspace, Path::new("Result.nib"), &matcher)
        .unwrap();
    assert_eq!(
        std::fs::read(workspace.join("Result.nib/objects.nib")).unwrap(),
        b"validated bytes"
    );
    assert!(artifact
        .publish(&workspace, Path::new("Result.nib"), &matcher)
        .is_err());
    assert_eq!(
        std::fs::read(workspace.join("Result.nib/objects.nib")).unwrap(),
        b"validated bytes"
    );
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), workspace.join("escape")).unwrap();
    assert!(artifact
        .publish(&workspace, Path::new("escape/Result.nib"), &matcher)
        .is_err());
    assert!(!outside.path().join("Result.nib").exists());
    assert!(artifact
        .publish(&workspace, Path::new(".env/Result.nib"), &matcher)
        .is_err());
}

#[test]
fn compiler_artifact_links_hardlinks_and_special_files_are_rejected() {
    let compiler = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), b"host canary").unwrap();
    let nib = compiler.path().join("Compiled.nib");
    symlink(outside.path(), &nib).unwrap();
    assert!(Artifact::read(&Dir::open(compiler.path()).unwrap()).is_err());
    std::fs::remove_file(&nib).unwrap();
    std::fs::hard_link(outside.path(), &nib).unwrap();
    assert!(Artifact::read(&Dir::open(compiler.path()).unwrap()).is_err());
    std::fs::remove_file(&nib).unwrap();
    std::fs::create_dir(&nib).unwrap();
    symlink(outside.path(), nib.join("canary")).unwrap();
    assert!(Artifact::read(&Dir::open(compiler.path()).unwrap()).is_err());
    std::fs::remove_file(nib.join("canary")).unwrap();
    use std::os::unix::ffi::OsStrExt;
    let fifo = std::ffi::CString::new(nib.join("fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(Artifact::read(&Dir::open(compiler.path()).unwrap()).is_err());
}

#[test]
fn protected_artifact_contents_are_rejected_before_publication() {
    let compiler = tempfile::tempdir().unwrap();
    let nib = compiler.path().join("Compiled.nib");
    std::fs::create_dir(&nib).unwrap();
    std::fs::write(nib.join(".env"), b"invalid output").unwrap();
    let artifact = Artifact::read(&Dir::open(compiler.path()).unwrap()).unwrap();
    let session = tempfile::tempdir().unwrap();
    let workspace = session.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    assert!(artifact
        .publish(
            &workspace,
            Path::new("Result.nib"),
            &Matcher::new(&Config::for_host()).unwrap()
        )
        .is_err());
    assert!(!workspace.join("Result.nib").exists());
}

#[test]
fn empty_directories_also_consume_the_artifact_entry_budget() {
    let compiler = tempfile::tempdir().unwrap();
    let nib = compiler.path().join("Compiled.nib");
    std::fs::create_dir(&nib).unwrap();
    for n in 0..4097 {
        std::fs::create_dir(nib.join(n.to_string())).unwrap();
    }
    let error = Artifact::read(&Dir::open(compiler.path()).unwrap())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("entry-count"), "{error}");
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "REAL constrained XIB compilation: explicit Xcode/runtime approval; run from Terminal"]
fn isolated_compiler_produces_a_nib_without_applying_source() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join(".env"), b"SYNTHETIC_XIB_HOST_CANARY").unwrap();
    let mut config = Config::for_host();
    config.toolchains.ios = Some(runboundary::policy::toolchains::Ios {
        xcode_app: std::env::var_os("RUNBOUNDARY_TEST_XCODE_APP")
            .expect("explicit Xcode approval required")
            .into(),
    });
    let runtime = std::env::var_os("RUNBOUNDARY_TEST_SIMULATOR_RUNTIME")
        .expect("explicit runtime approval required");
    let result = runboundary::interface_builder::compile(
        project.path(),
        &config,
        Path::new(&runtime),
        &request(),
    )
    .unwrap();
    assert!(!result.artifact.files.is_empty());
    let session = tempfile::tempdir().unwrap();
    let workspace = session.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    result
        .artifact
        .publish(
            &workspace,
            Path::new("Result.nib"),
            &Matcher::new(&config).unwrap(),
        )
        .unwrap();
    assert!(workspace.join("Result.nib").exists());
    assert!(!project.path().join("Result.nib").exists());
    println!("Compiled and validated a real NIB; original project unchanged. This does not certify all helper operations or full application builds.");
}
