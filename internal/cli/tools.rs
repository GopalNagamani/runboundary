//! Local manifest-name detection plus actual sandboxed executable checks.
use crate::{
    policy::{config::Config, matcher::Matcher},
    sandbox::{backend::Backend, process},
    security::{audit, paths::Dir},
    workspace::prepare,
};
use anyhow::Result;
use std::{path::Path, process::Stdio};

pub fn execute(root: &Path, check: bool) -> Result<i32> {
    let config = Config::load(root)?;
    let backend = Backend::select(root, &config)?;
    let dir = Dir::open(root)?;
    println!("RunBoundary Toolchains\n");
    for (label, marker) in [
        ("Node/web", "package.json"),
        ("Rust", "Cargo.toml"),
        ("Python", "pyproject.toml"),
        ("Python", "requirements.txt"),
        ("Go", "go.mod"),
        ("Java/Android Gradle", "gradlew"),
        ("Java Maven", "pom.xml"),
        ("Flutter", "pubspec.yaml"),
        ("C/C++", "CMakeLists.txt"),
        ("Swift", "Package.swift"),
    ] {
        if let Ok((parent, name)) = dir.parent(Path::new(marker)) {
            if parent.metadata(&name).is_ok() {
                println!("[INFO] {label} marker: {marker} (contents not inspected)");
            }
        }
    }
    for name in dir.entries()? {
        if matches!(
            name.extension().and_then(|x| x.to_str()),
            Some("xcodeproj" | "xcworkspace")
        ) {
            println!("[INFO] Xcode project marker: {name:?} (contents not inspected)");
        }
    }
    for path in backend.tool_roots() {
        println!("[INFO] Explicit read-only SDK tree: {path:?} (all its contents are visible)");
    }
    println!("[INFO] Caches are private and disposable; host caches and signing credentials are not imported.");
    println!("[INFO] Emulator/Simulator, USB device bridges, GUI sessions and signing integration are not implemented.");
    if config.toolchains.ios.is_some() {
        println!("[INFO] iOS XIB/storyboard compilation is currently unsupported: Interface Builder can require blocked CoreSimulator services even for an unsigned build.");
    }
    println!("[INFO] Version checks do not certify a complete SDK build or device workflow.");
    if !check {
        println!("Run runb tools --check to execute checks inside the OS sandbox.");
        return Ok(0);
    }
    let matcher = Matcher::new(&config)?;
    let work = prepare::prepare(&dir, &matcher)?;
    let env = backend.environment(&config, &[], work.path())?;
    let result = (|| -> Result<i32> {
        backend.probe(root, work.path(), &env)?;
        println!("[PASS] Actual sandbox preflight verified");
        let mut checks = backend.tool_checks().to_vec();
        let mut failed = false;
        let node_project = dir.metadata(std::ffi::OsStr::new("package.json")).is_ok();
        let python_project = ["pyproject.toml", "requirements.txt"]
            .iter()
            .any(|p| dir.metadata(std::ffi::OsStr::new(p)).is_ok());
        let python = if cfg!(target_os = "macos") {
            "python3.12"
        } else {
            "python3"
        };
        // Missing optional runtimes are not counted as passes. A matching
        // project marker makes the runtime required for this check.
        for (label, command, flag, required) in [
            ("Node", "node", "--version", node_project),
            ("Python", python, "--version", python_project),
        ] {
            if backend.resolve(command).is_ok() {
                checks.push((label.into(), vec![command.into(), flag.into()]));
            } else {
                println!("[UNAVAILABLE] {label} executable in approved runtimes");
                failed |= required;
            }
        }
        for (needed, label, command, flag) in [
            (
                config.toolchains.rust.is_none()
                    && dir.metadata(std::ffi::OsStr::new("Cargo.toml")).is_ok(),
                "Rust compiler",
                "rustc",
                "--version",
            ),
            (
                config.toolchains.go.is_none()
                    && dir.metadata(std::ffi::OsStr::new("go.mod")).is_ok(),
                "Go compiler",
                "go",
                "version",
            ),
            (
                config.toolchains.java.is_none()
                    && ["gradlew", "pom.xml"]
                        .iter()
                        .any(|p| dir.metadata(std::ffi::OsStr::new(p)).is_ok()),
                "Java compiler",
                "javac",
                "-version",
            ),
        ] {
            if needed {
                if backend.resolve(command).is_ok() {
                    checks.push((label.into(), vec![command.into(), flag.into()]));
                } else {
                    failed = true;
                    println!("[UNAVAILABLE] {label}; install in an approved runtime or configure its toolchain root");
                }
            }
        }
        if checks.is_empty() {
            println!(
                "[INFO] No version-check executables configured; sandbox preflight alone passed."
            );
        }
        for (label, args) in checks {
            let exe = backend.resolve(&args[0])?;
            let mut command = backend.command(root, work.path(), &env, &exe, &args[1..])?;
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let status = process::interactive(&mut command)?;
            if status.success() {
                println!("[PASS] {label} check command exited successfully inside sandbox");
            } else {
                failed = true;
                println!("[FAIL] {label} check command: {}. Full SDK build is not verified; no extra permissions were granted.",process::exit_code(status));
            }
        }
        audit::log(
            root,
            "toolchain_check_completed",
            "sandboxed version checks; no build, emulator or signing certification",
        )?;
        Ok(if failed { 1 } else { 0 })
    })();
    backend.cleanup_private_dirs(work.path(), &env)?;
    result
}
