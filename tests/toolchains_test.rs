use runboundary::{
    policy::{
        config::Config,
        matcher::Matcher,
        toolchains::{Java, Toolchains},
    },
    sandbox::backend::Backend,
    security::paths::Dir,
    workspace::prepare,
};
use std::{os::unix::fs::PermissionsExt, path::Path};

#[test]
fn toolchain_config_is_opt_in_strict_and_paths_cannot_traverse() {
    assert!(Config::defaults().toolchains.is_empty());
    let typo = "java:\n  home: /opt/jdk\n  inherit_credentials: true\n";
    assert!(serde_yaml::from_str::<Toolchains>(typo).is_err());
    for path in ["relative/jdk", "/opt/../home/user"] {
        let t = Toolchains {
            java: Some(Java { home: path.into() }),
            ..Toolchains::default()
        };
        assert!(t.validate_syntax().is_err());
    }
    let root = tempfile::tempdir().unwrap();
    let mut c = Config::for_host();
    c.toolchains.java = Some(Java {
        home: root.path().into(),
    });
    assert!(Backend::select(root.path(), &c).is_err());
}
#[test]
fn private_build_caches_do_not_import_environment_or_home_state() {
    use std::collections::BTreeMap;
    let mut env = BTreeMap::from([
        ("HOME".into(), "/private-session/home".into()),
        ("JAVA_HOME".into(), "/approved/jdk".into()),
    ]);
    runboundary::policy::toolchains::private_environment(&mut env);
    for key in [
        "CARGO_HOME",
        "CARGO_TARGET_DIR",
        "GRADLE_USER_HOME",
        "ANDROID_USER_HOME",
        "GOCACHE",
        "GOMODCACHE",
        "PIP_CACHE_DIR",
        "npm_config_cache",
    ] {
        assert!(env[key].starts_with("/private-session/home/"));
    }
    assert!(!env.contains_key("OPENAI_API_KEY"));
    assert!(!env.contains_key("SSH_AUTH_SOCK"));
    assert_eq!(env["JAVA_HOME"], "/approved/jdk");
}
#[test]
fn workspace_executable_plan_preserves_arguments_and_rejects_traversal_links() {
    let root = tempfile::tempdir().unwrap();
    let c = Config::for_host();
    let backend = Backend::select(root.path(), &c).unwrap();
    std::fs::write(root.path().join("build task.sh"), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(
        root.path().join("build task.sh"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let malicious = "literal; $(touch SHOULD_NOT_RUN)";
    let (exe, args) = runboundary::cli::preview::command_plan(
        &backend,
        root.path(),
        &["./build task.sh".into(), malicious.into()],
    )
    .unwrap();
    assert!(exe.is_absolute());
    assert_eq!(args[1], r#"exec "$@""#);
    assert_eq!(args.last().unwrap(), malicious);
    assert!(!root.path().join("SHOULD_NOT_RUN").exists());
    for path in ["./../escape", "./", "./folder/../task"] {
        assert!(
            runboundary::cli::preview::command_plan(&backend, root.path(), &[path.into()]).is_err()
        );
    }
    std::os::unix::fs::symlink("build task.sh", root.path().join("alias")).unwrap();
    assert!(
        runboundary::cli::preview::command_plan(&backend, root.path(), &["./alias".into()])
            .is_err()
    );
}
#[test]
fn build_and_package_credentials_remain_mandatory_protections() {
    let mut c = Config::defaults();
    c.filesystem.protected.clear();
    let matcher = Matcher::new(&c).unwrap();
    for path in [
        "release.jks",
        "release.keystore",
        "cert.p12",
        "cert.pfx",
        "app.mobileprovision",
        "key.properties",
        "keystore.properties",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".m2/settings.xml",
    ] {
        assert!(matcher.protected(Path::new(path)), "{path}");
    }
    assert!(!matcher.protected(Path::new("gradlew")));
    assert!(!matcher.protected(Path::new("build.gradle.kts")));
}
#[test]
#[ignore = "REAL OS toolchain test: requires supported sandbox from Terminal; synthetic SDK only"]
fn approved_sdk_is_read_only_and_workspace_wrapper_runs_only_in_sandbox() {
    // Synthetic SDK and project are private siblings in the trusted checkout.
    // No host cache or real SDK/credential is imported. /tmp checkouts fail
    // trust validation explicitly rather than weakening permission checks.
    let fixture = tempfile::Builder::new()
        .prefix(".runboundary-sdk-test-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let sdk = fixture.path().join("jdk");
    std::fs::create_dir_all(sdk.join("bin")).unwrap();
    for name in ["java", "javac"] {
        std::fs::write(
            sdk.join("bin").join(name),
            "#!/bin/sh\nprintf synthetic-jdk\n",
        )
        .unwrap();
        std::fs::set_permissions(
            sdk.join("bin").join(name),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    std::fs::write(sdk.join("sdk-marker"), "SYNTHETIC_SDK").unwrap();
    let project = fixture.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join(".env"), "SYNTHETIC_HOST_SECRET").unwrap();
    let mut c = Config::for_host();
    c.toolchains.java = Some(Java { home: sdk.clone() });
    if cfg!(target_os = "macos") {
        if let Some(runtime) = std::env::var_os("RUNBOUNDARY_TEST_RUNTIME_ROOT") {
            c.sandbox.runtime_roots.push(runtime.into());
        }
    }
    let backend = Backend::select(&project, &c).unwrap();
    let matcher = Matcher::new(&c).unwrap();
    let script = r#"#!/bin/sh
set -eu
[ "$1" = 'literal; $(touch SHOULD_NOT_RUN)' ]
[ -f "$JAVA_HOME/sdk-marker" ]
"$JAVA_HOME/bin/javac" -version >/dev/null
! (printf changed > "$JAVA_HOME/sdk-marker") 2>/dev/null
! cat .env >/dev/null 2>&1
! cat "$2/.env" >/dev/null 2>&1
case "$GRADLE_USER_HOME" in "$HOME"/*) ;; *) exit 9;; esac
printf private > "$GRADLE_USER_HOME/cache-marker"
printf built > result.txt
"#;
    std::fs::write(project.join("build task.sh"), script).unwrap();
    std::fs::set_permissions(
        project.join("build task.sh"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let work = prepare::prepare(&Dir::open(&project).unwrap(), &matcher).unwrap();
    let workspace = work.path().canonicalize().unwrap();
    let env = backend.environment(&c, &[], &workspace).unwrap();
    backend.probe(&project, &workspace, &env).unwrap();
    let (exe, args) = runboundary::cli::preview::command_plan(
        &backend,
        &workspace,
        &[
            "./build task.sh".into(),
            "literal; $(touch SHOULD_NOT_RUN)".into(),
            project.to_str().unwrap().into(),
        ],
    )
    .unwrap();
    let output = backend
        .preview_command(&project, &workspace, &env, &exe, &args, false)
        .unwrap()
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(sdk.join("sdk-marker")).unwrap(),
        b"SYNTHETIC_SDK"
    );
    assert_eq!(
        std::fs::read(workspace.join("result.txt")).unwrap(),
        b"built"
    );
    assert!(!project.join("result.txt").exists());
    assert!(!workspace.join("SHOULD_NOT_RUN").exists());
    backend.cleanup_private_dirs(&workspace, &env).unwrap();
    assert!(!workspace.parent().unwrap().join("sandbox-home").exists());
}

#[test]
fn sdk_layout_validation_rejects_external_executables_and_writable_trees() {
    let fixture = tempfile::Builder::new()
        .prefix(".runboundary-sdk-validation-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap();
    std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let project = fixture.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let sdk = fixture.path().join("jdk");
    std::fs::create_dir_all(sdk.join("bin")).unwrap();
    for name in ["java", "javac"] {
        std::fs::write(sdk.join("bin").join(name), "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(
            sdk.join("bin").join(name),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let mut c = Config::for_host();
    c.toolchains.java = Some(Java { home: sdk.clone() });
    let bindings = c.toolchains.bindings(&project).unwrap();
    assert_eq!(
        bindings.environment["JAVA_HOME"],
        sdk.canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(bindings.roots, vec![sdk.canonicalize().unwrap()]);
    std::fs::remove_file(sdk.join("bin/javac")).unwrap();
    std::os::unix::fs::symlink("/bin/sh", sdk.join("bin/javac")).unwrap();
    assert!(c.toolchains.bindings(&project).is_err());
    std::fs::remove_file(sdk.join("bin/javac")).unwrap();
    std::fs::write(sdk.join("bin/javac"), "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(
        sdk.join("bin/javac"),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    assert!(c.toolchains.bindings(&project).is_err());
}

#[test]
fn tools_detection_does_not_execute_project_scripts_or_print_manifest_contents() {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("runboundary.yaml"),
        serde_yaml::to_string(&Config::for_host()).unwrap(),
    )
    .unwrap();
    std::fs::write(
        project.path().join("package.json"),
        "SYNTHETIC_MANIFEST_CONTENT_NOT_TO_PRINT",
    )
    .unwrap();
    let marker = project.path().join("HOST_EXECUTED");
    let quoted = marker.to_str().unwrap().replace('\'', "'\\''");
    std::fs::write(
        project.path().join("gradlew"),
        format!("#!/bin/sh\nprintf ran > '{quoted}'\n"),
    )
    .unwrap();
    std::fs::set_permissions(
        project.path().join("gradlew"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_runb"))
        .args(["--project", project.path().to_str().unwrap(), "tools"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Node/web marker"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SYNTHETIC_MANIFEST_CONTENT"));
    assert!(!marker.exists());
}
