//! Fixed XIB experiments; helper connections require a separate explicit opt-in.
#![cfg(target_os = "macos")]
use runboundary::{
    policy::{config::Config, matcher::Matcher, toolchains::Ios},
    sandbox::{backend::Backend, process},
    security::paths::Dir,
    workspace::prepare,
};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};
#[path = "support/macos_diagnostic.rs"]
mod diagnostic;
use diagnostic::{candidate_command, candidate_with_parameters, capture, capture_process_tree};

const XIB: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<document type="com.apple.InterfaceBuilder3.CocoaTouch.XIB" version="3.0" toolsVersion="23501" targetRuntime="iOS.CocoaTouch" propertyAccessControl="none" useAutolayout="YES" useTraitCollections="YES" useSafeAreas="YES" colorMatched="YES">
 <device id="retina6_12" orientation="portrait" appearance="light"/>
 <dependencies><deployment identifier="iOS"/><plugIn identifier="com.apple.InterfaceBuilder.IBCocoaTouchPlugin" version="23501"/><capability name="Safe area layout guides" minToolsVersion="9.0"/></dependencies>
 <objects>
  <placeholder placeholderIdentifier="IBFilesOwner" id="owner" userLabel="File's Owner" customClass="NSObject"/>
  <placeholder placeholderIdentifier="IBFirstResponder" id="responder" customClass="UIResponder"/>
  <view contentMode="scaleToFill" id="view"><rect key="frame" x="0.0" y="0.0" width="320" height="480"/><viewLayoutGuide key="safeArea" id="safe"/></view>
 </objects>
</document>
"#;
const DENY_SIMULATOR: &str = r#"
(deny mach-lookup
 (global-name "com.apple.CoreSimulator.CoreSimulatorService")
 (global-name "com.apple.CoreSimulator.CoreSimulatorService.xpc")
 (global-name "com.apple.CoreSimulator.simdiskimaged"))
"#;
const ALLOW_LAUNCH_HOST: &str = r#"
(allow mach-lookup (global-name "com.apple.CoreSimulator.SimLaunchHost-arm64"))
"#;
const ALLOW_SIMULATOR: &str = r#"
(allow mach-lookup
 (global-name "com.apple.CoreSimulator.CoreSimulatorService")
 (global-name "com.apple.CoreSimulator.CoreSimulatorService.xpc")
 (xpc-service-name "com.apple.CoreSimulator.CoreSimulatorService")
 (global-name "com.apple.CoreSimulator.simdiskimaged")
 (global-name "com.apple.CoreSimulator.SimLaunchHost-arm64"))
"#;

fn runtime_root(path: &Path) -> PathBuf {
    let actual = path.canonicalize().expect("approved runtime must exist");
    assert!(actual.starts_with("/Library/Developer/CoreSimulator/Volumes"));
    assert_eq!(
        actual.extension().and_then(|s| s.to_str()),
        Some("simruntime")
    );
    assert!(actual.join("Contents/Resources/RuntimeRoot").is_dir());
    root_controlled(&actual);
    actual
}
fn root_controlled(path: &Path) {
    let admin = unsafe { libc::getgrnam(c"admin".as_ptr()) };
    assert!(!admin.is_null(), "macOS administrator group is unavailable");
    let admin_gid = unsafe { (*admin).gr_gid };
    for ancestor in path.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor).unwrap();
        assert!(meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o6002 == 0
                && (meta.mode() & 0o020 == 0 || meta.gid() == admin_gid),
            "diagnostic SDK paths must be real root-owned directories without world writes, non-admin group writes or set-ID bits: {ancestor:?}");
    }
}

#[test]
#[ignore = "REAL fixed-XIB diagnostic: explicitly approve Xcode and one installed runtime; Terminal required"]
fn diagnose_interface_builder() {
    let test_helpers =
        std::env::var("RUNBOUNDARY_TEST_ALLOW_SIMULATOR_SERVICES").is_ok_and(|value| value == "1");
    if test_helpers {
        assert_eq!(
            std::env::consts::ARCH,
            "aarch64",
            "the experimental helper names currently target Apple silicon only"
        );
        println!("Explicit diagnostic-only helper connection approval. Shared host helpers may use account Simulator state; containment is not certified.");
    }
    let app =
        std::env::var_os("RUNBOUNDARY_TEST_XCODE_APP").expect("explicit Xcode approval required");
    let runtime = runtime_root(&PathBuf::from(
        std::env::var_os("RUNBOUNDARY_TEST_SIMULATOR_RUNTIME")
            .expect("explicit installed runtime approval required"),
    ));
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("Synthetic.xib"), XIB).unwrap();
    std::fs::write(project.path().join(".env"), "SYNTHETIC_IBTOOL_HOST_CANARY").unwrap();
    let mut config = Config::for_host();
    config.toolchains.ios = Some(Ios {
        xcode_app: app.into(),
    });
    let backend = Backend::select(project.path(), &config).unwrap();
    let matcher = Matcher::new(&config).unwrap();
    let args: Vec<String> = [
        "--errors",
        "--warnings",
        "--notices",
        "--target-device",
        "iphone",
        "--minimum-deployment-target",
        "17.2",
        "--output-format",
        "human-readable-text",
        "--compile",
        "Synthetic.nib",
        "Synthetic.xib",
    ]
    .map(String::from)
    .into();
    let executable = backend.resolve("ibtool").unwrap();
    let direct = backend.resolve("ibtoold").unwrap();
    let mut pids = Vec::new();
    let mut host_ok = false;
    let mut production_ok = false;
    let mut candidates = Vec::new();
    let mut modes = vec![
        "host-synthetic-control",
        "production-profile",
        "direct-compiler",
        "private-runtime-catalog",
        "private-runtime-root-environment",
    ];
    if test_helpers {
        modes.extend([
            "private-runtime-launch-helper",
            "private-runtime-simulator-helpers",
        ]);
    }
    for label in modes {
        let work = prepare::prepare(&Dir::open(project.path()).unwrap(), &matcher).unwrap();
        let mut env = backend.environment(&config, &[], work.path()).unwrap();
        // Refuse synthetic work too when the production boundary cannot start.
        backend.probe(project.path(), work.path(), &env).unwrap();
        let mut rules = DENY_SIMULATOR.to_owned();
        if label == "private-runtime-launch-helper" {
            rules.push_str(ALLOW_LAUNCH_HOST);
        } else if label == "private-runtime-simulator-helpers" {
            // Remove the explicit deny for this fixed experiment only. Do not
            // append allows after it and assume SBPL precedence overrides it.
            rules = ALLOW_SIMULATOR.to_owned();
        }
        let mut parameters = Vec::new();
        if label.starts_with("private-runtime") {
            let catalog =
                Path::new(&env["HOME"]).join("Library/Developer/CoreSimulator/Profiles/Runtimes");
            std::fs::create_dir_all(&catalog).unwrap();
            std::os::unix::fs::symlink(&runtime, catalog.join(runtime.file_name().unwrap()))
                .unwrap();
            // Selected public runtime + device descriptions; service access is
            // a separate opt-in above. No host home or writable SDK grant.
            for (parameter, path) in [
                ("IB_RUNTIME", runtime.as_path()),
                (
                    "IB_DEVICE_TYPES",
                    Path::new("/Library/Developer/CoreSimulator/Profiles/DeviceTypes"),
                ),
                ("IB_DEVICE_KIT", Path::new("/Library/Developer/DeviceKit")),
            ] {
                root_controlled(path);
                rules.push_str(&format!(
                    "\n(allow file-read* file-map-executable (subpath (param \"{parameter}\")))\n"
                ));
                parameters.push((parameter, path.to_str().unwrap()));
            }
            env.insert("IBToolNeverDeque".into(), "1".into());
            // Runtime enumeration may list these public parent directories.
            // Literal reads do not grant access to other Developer subtrees.
            if label.ends_with("helper") || label.ends_with("helpers") {
                rules.push_str(
                    r#"
(allow file-read* (literal "/Library") (literal "/Library/Developer")
 (literal "/Library/Developer/CoreSimulator")
 (literal "/Library/Developer/CoreSimulator/Profiles"))
"#,
                );
            }
            if label.ends_with("environment") {
                let runtime_root = runtime.join("Contents/Resources/RuntimeRoot");
                for key in ["SIMULATOR_ROOT", "IPHONE_SIMULATOR_ROOT"] {
                    env.insert(key.into(), runtime_root.to_str().unwrap().into());
                }
            }
        }
        let command = if label == "host-synthetic-control" {
            let mut command = Command::new(&executable);
            command
                .env_clear()
                .envs(&env)
                .current_dir(work.path())
                .args(&args);
            process::harden(&mut command);
            command
        } else {
            let compiler = if label == "production-profile" {
                &executable
            } else {
                &direct
            };
            let base = backend
                .command(project.path(), work.path(), &env, compiler, &args)
                .unwrap();
            if parameters.is_empty() {
                candidate_command(&base, &rules)
            } else {
                candidate_with_parameters(&base, &rules, &parameters)
            }
        };
        let (observed_pids, status_ok) = capture_process_tree(label, command);
        let output = work.path().join("Synthetic.nib");
        let ok = status_ok && output.exists() && !output.is_symlink();
        println!("{label}: compiled artifact present={}", output.exists());
        if label == "host-synthetic-control" {
            host_ok = ok;
        } else {
            pids.extend(observed_pids);
            if label == "production-profile" {
                production_ok = ok;
            } else if ok {
                candidates.push(label);
            }
            // Apply each candidate's exact permissions to a subprocess canary
            // probe too. Never call a compile success an isolation success.
            let check = String::from("! /bin/cat \"$1/.env\" >/dev/null 2>&1 && ! /bin/ls \"$1\" >/dev/null 2>&1 && [ \"$CFFIXED_USER_HOME\" = \"$HOME\" ]");
            let base = backend
                .command(
                    project.path(),
                    work.path(),
                    &env,
                    &backend.resolve("sh").unwrap(),
                    &[
                        "-c".into(),
                        check,
                        "canary".into(),
                        project.path().to_str().unwrap().into(),
                    ],
                )
                .unwrap();
            let (_, confined) = capture(
                &format!("{label}/original-project-canary"),
                candidate_with_parameters(&base, &rules, &parameters),
            );
            assert!(
                confined,
                "candidate violated project isolation; do not promote it"
            );
        }
        backend.cleanup_private_dirs(work.path(), &env).unwrap();
    }
    println!("Successful compilation candidates: {candidates:?}; helper-mode approval={test_helpers}. Direct canary checks do not certify service-launched work.");
    let pid_filter = pids
        .iter()
        .map(|pid| format!("eventMessage CONTAINS \"({pid})\""))
        .collect::<Vec<_>>()
        .join(" OR ");
    for (label, filter) in [("service-denials", "eventMessage CONTAINS \"mach-lookup\""),
        ("other-denials", "NOT (eventMessage CONTAINS \"mach-lookup\" OR eventMessage CONTAINS \"/private/etc/passwd\" OR eventMessage CONTAINS \"/System/Cryptexes/\" OR eventMessage CONTAINS \"/System/Volumes/Data\")")] {
        let predicate = format!("(process == \"kernel\" OR process == \"sandboxd\" OR subsystem BEGINSWITH \"com.apple.sandbox\") AND ({pid_filter}) AND ({filter})");
        let mut log = Command::new("/usr/bin/log");
        log.env_clear().args(["show", "--last", "5m", "--style", "compact", "--info", "--debug", "--predicate", &predicate]);
        process::harden(&mut log);
        capture(label, log);
    }
    assert!(
        host_ok,
        "fixed XIB host control failed; runtime functionality is not established"
    );
    assert!(production_ok, "production Interface Builder compilation remains unsupported; candidate success is not production support");
}
