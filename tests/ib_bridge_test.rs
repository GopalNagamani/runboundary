use agentvault::{
    ib_bridge::client::{parse, remap_dependencies},
    interface_builder::build::{Files, Job, Kind, Options},
};
use std::path::{Path, PathBuf};
#[path = "support/asset_catalog.rs"]
#[cfg(target_os = "macos")]
mod asset_fixture;
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}

#[test]
fn simulator_service_authority_requires_a_host_cli_flag() {
    use agentvault::cli::{Cli, Commands};
    use clap::Parser;
    let args = [
        "agentvault",
        "ios-build",
        "--workspace",
        "App.xcworkspace",
        "--scheme",
        "App",
        "--simulator-runtime",
        "/runtime",
    ];
    assert!(matches!(
        Cli::try_parse_from(args).unwrap().command,
        Commands::IosBuild {
            allow_compiler_simulator_services: false,
            ..
        }
    ));
    assert!(matches!(
        Cli::try_parse_from(
            args.into_iter()
                .chain(["--allow-compiler-simulator-services"])
        )
        .unwrap()
        .command,
        Commands::IosBuild {
            allow_compiler_simulator_services: true,
            ..
        }
    ));
    for field in [
        "allow_compiler_simulator_services",
        "simulator_services",
        "services",
    ] {
        let mut job = serde_json::json!({"operation": "version", "format": "xml"});
        job[field] = serde_json::json!(true);
        assert!(serde_json::from_value::<Job>(job).is_err());
    }
    assert!(parse(&strings(&[
        "--allow-compiler-simulator-services",
        "--version"
    ]))
    .is_err());
}

#[cfg(target_os = "macos")]
fn compiler_services() -> agentvault::interface_builder::SimulatorServices {
    use agentvault::interface_builder::SimulatorServices;
    if std::env::var("AGENTVAULT_TEST_COMPILER_SIMULATOR_SERVICES").as_deref() == Ok("1") {
        SimulatorServices::Enabled
    } else {
        SimulatorServices::Restricted
    }
}

#[test]
fn xcode_xib_storyboard_and_link_invocations_become_typed_operations() {
    let call = parse(&strings(&[
        "--errors",
        "--warnings",
        "--notices",
        "--module",
        "Fixture",
        "--output-partial-info-plist",
        "/build/Sample.plist",
        "--auto-activate-custom-fonts",
        "--target-device",
        "iphone",
        "--target-device",
        "ipad",
        "--minimum-deployment-target",
        "17.2",
        "--generate-dependency-info",
        "/build/Sample.dep",
        "--output-format",
        "human-readable-text",
        "--compile",
        "/build/Sample.nib",
        "/copy/Sample.xib",
    ]))
    .unwrap();
    assert!(matches!(
        call.job,
        Job::Compile {
            kind: Kind::Xib,
            ..
        }
    ));
    assert!(call.partial.is_some());
    assert!(call.dependencies.is_some());
    let call = parse(&strings(&[
        "--compilation-directory",
        "/build/Resources",
        "/copy/Main.storyboard",
    ]))
    .unwrap();
    assert!(matches!(
        call.job,
        Job::Compile {
            kind: Kind::Storyboard,
            ..
        }
    ));
    assert_eq!(
        call.destination.unwrap(),
        Path::new("/build/Resources/Main.storyboardc")
    );
    let call = parse(&strings(&[
        "--link",
        "/build/App.app",
        "/build/Main.storyboardc",
        "/build/Launch.storyboardc",
    ]))
    .unwrap();
    assert!(matches!(call.job, Job::Link { .. }));
    assert!(matches!(
        parse(&strings(&["--version", "--output-format", "xml1"]))
            .unwrap()
            .job,
        Job::Version { .. }
    ));
}
#[test]
fn command_plugin_environment_and_runtime_escape_options_are_rejected() {
    assert!(parse(&strings(&["--version", "--module", "Fixture"])).is_err());
    assert!(parse(&strings(&["--version", "--version"])).is_err());
    for flag in [
        "--plugin",
        "--plugin-dir",
        "--execute",
        "--runtime",
        "--environment",
        "--write",
        "--compilation-mode-for-ios",
    ] {
        assert!(
            parse(&strings(&[
                flag,
                "/host/value",
                "--compile",
                "a.nib",
                "a.xib"
            ]))
            .is_err(),
            "{flag}"
        );
    }
    assert!(parse(&strings(&[
        "--module",
        "--evil",
        "--compile",
        "a.nib",
        "a.xib"
    ]))
    .is_err());
    assert!(parse(&strings(&[
        "--compile",
        "a.nib",
        "--compile",
        "b.nib",
        "a.xib"
    ]))
    .is_err());
    assert!(parse(&strings(&[
        "--platform",
        "iphoneos",
        "--compile",
        "a.nib",
        "a.xib"
    ]))
    .is_err());
}
#[test]
fn localized_compile_accepts_only_bounded_unique_locales_and_declared_strings() {
    let args = strings(&[
        "--companion-strings-file",
        "zh-Hans:/copy/zh-Hans.lproj/Main.strings",
        "--companion-strings-file",
        "pt_BR:/copy/pt_BR.lproj/Main.strings",
        "--compilation-directory",
        "/build/Base.lproj",
        "/copy/Base.lproj/Main.storyboard",
    ]);
    let call = parse(&args).unwrap();
    assert_eq!(call.companion_strings.len(), 2);
    assert_eq!(
        call.destination.unwrap(),
        Path::new("/build/Base.lproj/Main.storyboardc")
    );
    let mut files = Files::from([
        (
            PathBuf::from("Main.storyboard"),
            include_bytes!("fixtures/ib_build/LaunchScreen.storyboard").to_vec(),
        ),
        (
            PathBuf::from("Strings/zh-Hans.strings"),
            b"/* empty localization is valid */".to_vec(),
        ),
        (PathBuf::from("Strings/pt_BR.strings"), vec![]),
    ]);
    call.job.validate(&files).unwrap();
    files.remove(Path::new("Strings/pt_BR.strings"));
    files.insert(PathBuf::from("unexpected.strings"), vec![]);
    assert!(call.job.validate(&files).is_err());
    files.remove(Path::new("unexpected.strings"));
    files.insert(
        PathBuf::from("Strings/pt_BR.strings"),
        vec![0; 8 * 1024 * 1024 + 1],
    );
    assert!(call.job.validate(&files).is_err());
    for value in [
        "zh-Hans",
        "zh-Hans:",
        "zh-Hans:/copy/Main.xib",
        "../en:/copy/Main.strings",
        "/en:/copy/Main.strings",
        "en/../../outside:/copy/Main.strings",
        "Base:/copy/Main.strings",
        "en::/copy/Main.xib",
        "--evil:/copy/Main.strings",
        "en--US:/copy/Main.strings",
        "en\n:/copy/Main.strings",
    ] {
        assert!(
            parse(&strings(&[
                "--companion-strings-file",
                value,
                "--compile",
                "/build/Base.lproj/Main.storyboardc",
                "/copy/Main.storyboard",
            ]))
            .is_err(),
            "{value:?}"
        );
    }
    for operation in [
        vec!["--version"],
        vec!["--link", "/build/App.app", "/build/Main.storyboardc"],
        vec!["--compile", "/build/Main.nib", "/copy/Main.xib"],
    ] {
        let mut args = strings(&["--companion-strings-file", "en:/copy/Main.strings"]);
        args.extend(strings(&operation));
        assert!(parse(&args).is_err());
    }
    for duplicate in ["zh-Hans", "ZH-hans"] {
        let mut args = args.clone();
        args.extend(strings(&[
            "--companion-strings-file",
            &format!("{duplicate}:/copy/Other.strings"),
        ]));
        assert!(parse(&args).is_err());
    }
    // Host validation rejects forged typed requests independently of the parser.
    let mut job = serde_json::to_value(&call.job).unwrap();
    job["options"]["companion_locales"] = serde_json::json!(["../escape"]);
    let forged: Job = serde_json::from_value(job).unwrap();
    assert!(forged.validate(&Files::new()).is_err());
    let link = Job::Link {
        inputs: vec!["Main.storyboardc".into()],
        options: Options {
            companion_locales: vec!["en".into()],
            ..Options::default()
        },
    };
    assert!(link
        .validate(&Files::from([(
            PathBuf::from("Main.storyboardc/main.nib"),
            vec![1]
        )]))
        .is_err());
}
#[test]
fn typed_requests_validate_again_without_trusting_the_wrapper() {
    let job = Job::Compile {
        kind: Kind::Xib,
        input: "Source.xib".into(),
        output: "Source.nib".into(),
        options: Options::default(),
    };
    let files = Files::from([(
        PathBuf::from("Source.xib"),
        include_bytes!("fixtures/ib_build/SystemContent.xib").to_vec(),
    )]);
    assert!(job.validate(&files).is_ok());
    let escape = Job::Compile {
        kind: Kind::Xib,
        input: "../Source.xib".into(),
        output: "Source.nib".into(),
        options: Options::default(),
    };
    assert!(escape.validate(&files).is_err());
    let link = Job::Link {
        inputs: vec!["Main.storyboardc".into()],
        options: Options::default(),
    };
    assert!(link.validate(&files).is_err());
    let mut unknown = serde_json::to_value(job).unwrap();
    unknown["runtime"] = serde_json::json!("/host/runtime");
    assert!(serde_json::from_value::<Job>(unknown).is_err());
}
#[test]
fn dependency_info_remaps_staged_inputs_outputs_and_auxiliary_files() {
    let mappings = vec![
        ("Inputs/View.xib".into(), PathBuf::from("/copy/View.xib")),
        (
            "Aux/partial.plist".into(),
            PathBuf::from("/build/View.plist"),
        ),
    ];
    let bytes=b"\0ibtool\0\x10/stage/Inputs/View.xib\0\x10/SDK/UIKit.h\0\x40/stage/Outputs/View.nib\0\x40/stage/Aux/partial.plist\0";
    let result =
        remap_dependencies(bytes, "/stage", &mappings, Path::new("/build/App.app")).unwrap();
    assert_eq!(result,b"\0ibtool\0\x10/copy/View.xib\0\x10/SDK/UIKit.h\0\x40/build/App.app/View.nib\0\x40/build/View.plist\0");
    for invalid in [
        b"".as_slice(),
        b"\x10missing-version\0",
        b"\0unterminated",
        b"\0v\0\0v\0",
        b"\0v\0\x12unknown\0",
        b"\0v\0\x10/stage/Inputs/other.xib\0",
    ] {
        assert!(remap_dependencies(invalid, "/stage", &mappings, Path::new("/build")).is_err());
    }
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "REAL typed XIB/storyboard/link jobs: approve Xcode/runtime; Terminal required"]
fn typed_jobs_produce_xib_storyboard_link_and_auxiliary_outputs() {
    use agentvault::{
        interface_builder::build::{execute_with_services, Format},
        policy::{config::Config, toolchains::Ios},
    };
    use std::sync::atomic::AtomicBool;
    let services = compiler_services();
    let execute = |project: &Path,
                   config: &Config,
                   runtime: &Path,
                   job: &Job,
                   inputs: &Files,
                   cancel: &AtomicBool| {
        execute_with_services(project, config, runtime, job, inputs, cancel, services)
    };
    let root = tempfile::tempdir().unwrap();
    let runtime = std::env::var_os("AGENTVAULT_TEST_SIMULATOR_RUNTIME")
        .expect("explicit runtime approval required");
    let mut config = Config::for_host();
    config.toolchains.ios = Some(Ios {
        xcode_app: std::env::var_os("AGENTVAULT_TEST_XCODE_APP")
            .expect("explicit Xcode approval required")
            .into(),
    });
    let cancel = AtomicBool::new(false);
    let version = execute(
        root.path(),
        &config,
        Path::new(&runtime),
        &Job::Version {
            format: Format::Xml,
        },
        &Files::new(),
        &cancel,
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&version.stdout).contains("com.apple.ibtool.version"));
    let options = Options {
        partial_info: true,
        dependencies: true,
        ..Options::default()
    };
    let xib = Job::Compile {
        kind: Kind::Xib,
        input: "Sample.xib".into(),
        output: "Sample.nib".into(),
        options,
    };
    let input = Files::from([(
        PathBuf::from("Sample.xib"),
        include_bytes!("fixtures/ib_build/SystemContent.xib").to_vec(),
    )]);
    let result = execute(
        root.path(),
        &config,
        Path::new(&runtime),
        &xib,
        &input,
        &cancel,
    )
    .unwrap();
    assert!(result
        .files
        .keys()
        .any(|p| p.starts_with("Outputs/Sample.nib")));
    assert!(result.files.contains_key(Path::new("Aux/partial.plist")));
    let mappings = vec![
        (
            "Inputs/Sample.xib".into(),
            PathBuf::from("/copy/Sample.xib"),
        ),
        (
            "Aux/partial.plist".into(),
            PathBuf::from("/build/Sample.plist"),
        ),
        (
            "Aux/dependencies".into(),
            PathBuf::from("/build/Sample.dep"),
        ),
    ];
    let remapped = remap_dependencies(
        &result.files[Path::new("Aux/dependencies")],
        &result.stage_root,
        &mappings,
        Path::new("/build/App.app"),
    )
    .unwrap();
    assert!(!remapped
        .windows(result.stage_root.len())
        .any(|b| b == result.stage_root.as_bytes()));
    let storyboard = Job::Compile {
        kind: Kind::Storyboard,
        input: "LaunchScreen.storyboard".into(),
        output: "LaunchScreen.storyboardc".into(),
        options: Options {
            companion_locales: vec!["zh-Hans".into()],
            dependencies: true,
            ..Options::default()
        },
    };
    let input = Files::from([
        (
            PathBuf::from("LaunchScreen.storyboard"),
            include_bytes!("fixtures/ib_build/LaunchScreen.storyboard").to_vec(),
        ),
        (
            PathBuf::from("Strings/zh-Hans.strings"),
            include_bytes!("fixtures/ib_build/LaunchScreen.strings").to_vec(),
        ),
    ]);
    let compiled = execute(
        root.path(),
        &config,
        Path::new(&runtime),
        &storyboard,
        &input,
        &cancel,
    )
    .unwrap();
    assert!(compiled
        .files
        .keys()
        .any(|p| p.starts_with("Outputs/Base.lproj/LaunchScreen.storyboardc")));
    assert_eq!(
        compiled.files.get(Path::new("Outputs/Base.lproj/LaunchScreen.storyboardc/AgentVaultLocalization/zh-Hans/LaunchScreen.strings")),
        Some(&include_bytes!("fixtures/ib_build/LaunchScreen.strings").to_vec()),
        "compile must preserve companion bytes for the separate link job; outputs: {:?}", compiled.files.keys().collect::<Vec<_>>()
    );
    let dependencies = &compiled.files[Path::new("Aux/dependencies")];
    assert!(dependencies
        .windows(b"Inputs/Strings/zh-Hans.strings".len())
        .any(|s| s == b"Inputs/Strings/zh-Hans.strings"));
    let linked_inputs = compiled
        .files
        .into_iter()
        .filter_map(|(p, b)| p.strip_prefix("Outputs").ok().map(|p| (p.to_owned(), b)))
        .collect();
    let linked = execute(
        root.path(),
        &config,
        Path::new(&runtime),
        &Job::Link {
            inputs: vec!["Base.lproj/LaunchScreen.storyboardc".into()],
            options: Options::default(),
        },
        &linked_inputs,
        &cancel,
    )
    .unwrap();
    assert!(linked
        .files
        .keys()
        .any(|p| p.starts_with("Outputs/Base.lproj/LaunchScreen.storyboardc")));
    let translations = tempfile::NamedTempFile::new().unwrap();
    let strings = linked
        .files
        .get(Path::new("Outputs/zh-Hans.lproj/LaunchScreen.strings"))
        .unwrap_or_else(|| {
            panic!(
                "link must publish the translated strings; outputs: {:?}",
                linked.files.keys().collect::<Vec<_>>()
            )
        });
    std::fs::write(translations.path(), strings).unwrap();
    let plist = std::process::Command::new("/usr/bin/plutil")
        .args(["-convert", "xml1", "-o", "-"])
        .arg(translations.path())
        .output()
        .unwrap();
    assert!(plist.status.success());
    assert!(String::from_utf8_lossy(&plist.stdout).contains("准备就绪"));
    assert!(!linked.files.keys().any(|p| p
        .components()
        .any(|c| c.as_os_str() == "AgentVaultLocalization")));
    println!("Verified actual version, XIB+metadata, localized storyboard compile with companion strings, and storyboard link operations in the constrained compiler.");
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "REAL xcodebuild+IBC_EXEC fixture build: approve Xcode/runtime and run from Terminal"]
fn xcode_build_uses_the_broker_for_xib_storyboard_and_link_steps() {
    use agentvault::policy::{config::Config, toolchains::Ios};
    let root = tempfile::tempdir().unwrap();
    agentvault::cli::init::execute(root.path(), vec![]).unwrap();
    let mut config = Config::for_host();
    config.toolchains.ios = Some(Ios {
        xcode_app: std::env::var_os("AGENTVAULT_TEST_XCODE_APP")
            .expect("explicit Xcode approval required")
            .into(),
    });
    std::fs::write(
        root.path().join("agentvault.yaml"),
        serde_yaml::to_string(&config).unwrap(),
    )
    .unwrap();
    let files=[
        ("Fixture.xcodeproj/project.pbxproj",include_str!("fixtures/ib_build/project.pbxproj")),
        ("Fixture.xcodeproj/xcshareddata/xcschemes/Fixture.xcscheme",include_str!("fixtures/ib_build/Fixture.xcscheme")),
        ("Fixture.xcworkspace/contents.xcworkspacedata","<?xml version=\"1.0\"?><Workspace version=\"1.0\"><FileRef location=\"group:Fixture.xcodeproj\"/></Workspace>"),
        ("Sample.xib",include_str!("fixtures/ib_build/SystemContent.xib")),
        ("Base.lproj/LaunchScreen.storyboard",include_str!("fixtures/ib_build/LaunchScreen.storyboard")),
        ("zh-Hans.lproj/LaunchScreen.strings",include_str!("fixtures/ib_build/LaunchScreen.strings")),
        ("main.m","#import <UIKit/UIKit.h>\nint main(int argc,char **argv){@autoreleasepool{return UIApplicationMain(argc,argv,nil,nil);}}\n"),
        (".env","SYNTHETIC_IB_BUILD_CANARY"),
    ];
    for (name, bytes) in files {
        let file = root.path().join(name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, bytes).unwrap();
    }
    let assets = asset_fixture::files();
    for (name, bytes) in &assets {
        let file = root.path().join(name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, bytes).unwrap();
    }
    let runtime = std::env::var_os("AGENTVAULT_TEST_SIMULATOR_RUNTIME")
        .expect("explicit runtime approval required");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_agentvault"));
    if compiler_services() == agentvault::interface_builder::SimulatorServices::Enabled {
        command
            .arg("ios-build")
            .arg("--allow-compiler-simulator-services");
    } else {
        command.arg("ios-build");
    }
    let output = command
        .arg("--project")
        .arg(root.path())
        .args([
            "--workspace",
            "Fixture.xcworkspace",
            "--scheme",
            "Fixture",
            "--simulator-runtime",
        ])
        .arg(runtime)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("stdout={stdout}\nstderr={stderr}");
    assert!(
        output.status.success(),
        "fixture build failed: {}",
        output.status
    );
    assert!(stdout.contains("BUILD SUCCEEDED"));
    assert!(
        stdout.contains("--companion-strings-file zh-Hans:"),
        "fixture must exercise localized storyboard compilation"
    );
    assert!(stderr.contains("Interface Builder broker completed compile"));
    assert!(stderr.contains("Interface Builder broker completed link"));
    assert!(
        stderr.contains("Interface Builder broker completed asset tag query"),
        "asset tag discovery must use the isolated broker"
    );
    assert!(
        stderr.contains("Interface Builder broker completed asset catalog"),
        "asset catalog must use the isolated broker"
    );
    assert!(
        stdout.contains("GenerateAssetSymbols"),
        "fixture must exercise asset symbol generation"
    );
    for (name, bytes) in files {
        assert_eq!(
            std::fs::read(root.path().join(name)).unwrap(),
            bytes.as_bytes()
        );
    }
    assert!(!root.path().join("build").exists());
    for (name, bytes) in assets {
        assert_eq!(std::fs::read(root.path().join(name)).unwrap(), bytes);
    }
}
