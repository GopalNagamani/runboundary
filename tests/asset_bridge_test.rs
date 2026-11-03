use agentvault::{
    ib_bridge::assets::parse,
    interface_builder::{assets::Options, build::Job},
};
use std::path::{Path, PathBuf};
#[path = "support/asset_catalog.rs"]
mod fixture;
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}

#[test]
fn xcode_catalog_and_symbol_commands_become_path_free_typed_jobs() {
    let mut args = strings(&[
        "/copy/Assets.xcassets",
        "--compile",
        "/build/App.app",
        "--output-format",
        "human-readable-text",
        "--notices",
        "--warnings",
        "--export-dependency-info",
        "/build/Assets.dep",
        "--output-partial-info-plist",
        "/build/Assets.plist",
        "--app-icon",
        "AppIcon",
        "--compress-pngs",
        "--enable-on-demand-resources",
        "YES",
        "--development-region",
        "en",
        "--target-device",
        "iphone",
        "--minimum-deployment-target",
        "17.2",
        "--platform",
        "iphonesimulator",
    ]);
    let call = parse(&args).unwrap();
    call.job.validate(&fixture::files()).unwrap();
    assert_eq!(
        call.destination.as_deref(),
        Some(Path::new("/build/App.app"))
    );
    assert!(!serde_json::to_string(&call.job).unwrap().contains("/copy"));
    args.extend(strings(&[
        "--bundle-identifier",
        "com.worldtabletennis.iosapp",
        "--generate-swift-asset-symbol-extensions",
        "NO",
        "--generate-swift-asset-symbols",
        "/build/Symbols.swift",
        "--generate-objc-asset-symbols",
        "/build/Symbols.h",
        "--generate-asset-symbol-index",
        "/build/Symbols.plist",
    ]));
    let call = parse(&args).unwrap();
    call.job.validate(&fixture::files()).unwrap();
    assert_eq!(call.auxiliary.len(), 3);
    let Job::AssetCatalog { options, catalogs } = &call.job else {
        panic!("expected asset operation")
    };
    assert!(options.symbols());
    let compiler = options
        .arguments(catalogs, Path::new("/stage/compiler job"))
        .unwrap();
    assert_eq!(&compiler[..2], &["--persona", "actool"]);
    assert!(!compiler
        .iter()
        .any(|s| s.contains("/build") || s.contains("/copy")));
    assert!(compiler
        .iter()
        .any(|s| s == "/stage/compiler job/Aux/asset-symbols.swift"));
    assert!(compiler
        .iter()
        .any(|s| s == "/stage/compiler job/Inputs/Assets.xcassets"));
    assert!(compiler.iter().any(|s| s == "/stage/compiler job/Outputs"));
    assert!(compiler.windows(2).any(|pair| pair
        == [
            "--output-partial-info-plist",
            "/stage/compiler job/Aux/partial.plist"
        ]));
    assert!(!compiler
        .iter()
        .any(|s| s.starts_with("Inputs/") || s.starts_with("Aux/") || s == "Outputs"));
    assert!(options
        .arguments(catalogs, Path::new("relative/staging"))
        .is_err());
    assert!(matches!(
        parse(&strings(&["--version", "--output-format", "xml1"]))
            .unwrap()
            .job,
        Job::AssetVersion { .. }
    ));
}

#[test]
fn asset_tag_queries_are_path_free_and_reject_compilation_or_service_options() {
    let args = strings(&[
        "--print-asset-tag-combinations",
        "--output-format",
        "xml1",
        "/copy/Assets.xcassets",
    ]);
    let call = parse(&args).unwrap();
    let Job::AssetTagCombinations { catalogs } = &call.job else {
        panic!("expected asset tag query")
    };
    assert_eq!(catalogs, &["Assets.xcassets"]);
    assert!(call.destination.is_none());
    assert!(call.partial.is_none());
    assert!(call.dependencies.is_none());
    assert!(call.auxiliary.is_empty());
    assert!(!serde_json::to_string(&call.job).unwrap().contains("/copy"));
    call.job.validate(&fixture::files()).unwrap();
    let compiler = agentvault::interface_builder::assets::tag_arguments(
        catalogs,
        Path::new("/stage/compiler job"),
    )
    .unwrap();
    assert_eq!(
        compiler,
        strings(&[
            "--persona",
            "actool",
            "--print-asset-tag-combinations",
            "--output-format",
            "xml1",
            "/stage/compiler job/Inputs/Assets.xcassets",
        ])
    );
    for extra in [
        vec!["--compile", "/host/output"],
        vec!["--output-partial-info-plist", "/host/output"],
        vec!["--generate-swift-asset-symbols", "/host/output"],
        vec!["--allow-compiler-simulator-services"],
        vec!["--plugin", "/host/plugin"],
        vec!["--version"],
        vec!["--print-asset-tag-combinations"],
        vec!["--output-format", "xml1"],
        vec!["/another/assets.xcassets"],
        vec!["/copy/input.xib"],
    ] {
        let mut invalid = args.clone();
        invalid.extend(strings(&extra));
        assert!(parse(&invalid).is_err(), "{extra:?}");
    }
    assert!(parse(&strings(&["--print-asset-tag-combinations"])).is_err());
    assert!(parse(&strings(&[
        "--print-asset-tag-combinations",
        "--output-format",
        "human-readable-text",
        "/copy/Assets.xcassets",
    ]))
    .is_err());
    assert!(call.job.validate(&Default::default()).is_err());
    let mut outside = fixture::files();
    outside.insert("outside.json".into(), b"{}".to_vec());
    assert!(call.job.validate(&outside).is_err());
    assert!(agentvault::interface_builder::assets::tag_arguments(
        &["../Assets.xcassets".into()],
        Path::new("/stage"),
    )
    .is_err());
}

#[test]
fn app_icon_symbol_jobs_require_a_host_metadata_path_even_without_requested_metadata() {
    let catalogs = vec!["Assets.xcassets".into()];
    // The caller need not request metadata, but actool requires its destination
    // to generate symbols when an app icon is selected. A zero exit status is
    // otherwise possible with none of the requested symbol files produced.
    for (swift_symbols, objc_symbols, symbol_index) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let options = Options {
            app_icon: Some("AppIcon".into()),
            swift_symbols,
            objc_symbols,
            symbol_index,
            ..Options::default()
        };
        options.validate().unwrap();
        let args = options
            .arguments(&catalogs, Path::new("/stage/compiler job"))
            .unwrap();
        assert!(args.windows(2).any(|pair| pair
            == [
                "--output-partial-info-plist",
                "/stage/compiler job/Aux/partial.plist"
            ]));
        assert!(!options.partial_info);
    }
}

#[test]
fn asset_options_do_not_allow_commands_paths_runtime_or_service_overrides() {
    for flag in [
        "--plugin",
        "--plugin-dir",
        "--persona",
        "--environment",
        "--runtime",
        "--allow-compiler-simulator-services",
        "--asset-pack-output-specifications",
        "--sticker-pack-strings-file",
        "--write",
    ] {
        let mut args = strings(&["/copy/Assets.xcassets", "--compile", "/build/App.app"]);
        args.extend(strings(&[flag, "/host/value"]));
        assert!(parse(&args).is_err(), "{flag}");
    }
    for extra in [
        vec!["--platform", "iphoneos"],
        vec!["--target-device", "mac"],
        vec!["--app-icon", "../outside"],
        vec!["--development-region", "../../host"],
        vec!["--enable-on-demand-resources", "maybe"],
        vec!["--generate-swift-asset-symbol-extensions", "YES"],
        vec!["--compile", "/other"],
        vec!["--version"],
    ] {
        let mut args = strings(&["/copy/Assets.xcassets", "--compile", "/build/App.app"]);
        args.extend(strings(&extra));
        assert!(parse(&args).is_err(), "{extra:?}");
    }
    let job = Job::AssetCatalog {
        catalogs: vec!["Assets.xcassets".into()],
        options: Options::default(),
    };
    let mut value = serde_json::to_value(&job).unwrap();
    value["options"]["services"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Job>(value).is_err());
    let mut missing = fixture::files();
    missing.remove(Path::new("Assets.xcassets/Contents.json"));
    assert!(job.validate(&missing).is_err());
    let mut extra = fixture::files();
    extra.insert(PathBuf::from("outside.png"), vec![1]);
    assert!(job.validate(&extra).is_err());
    let forged = Job::AssetCatalog {
        catalogs: vec!["../Assets.xcassets".into()],
        options: Options::default(),
    };
    assert!(forged.validate(&fixture::files()).is_err());
    let forged = Job::AssetCatalog {
        catalogs: vec!["Assets.xcassets".into()],
        options: Options {
            bundle_identifier: Some("../../host".into()),
            ..Options::default()
        },
    };
    assert!(forged.validate(&fixture::files()).is_err());
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "REAL asset compiler and symbol jobs; explicit Xcode/runtime; Terminal required"]
fn typed_asset_jobs_produce_car_icons_symbols_and_metadata() {
    use agentvault::{
        interface_builder::{
            build::{execute_with_services, Files, Format},
            SimulatorServices,
        },
        policy::{config::Config, toolchains::Ios},
    };
    use std::sync::atomic::AtomicBool;
    let project = tempfile::tempdir().unwrap();
    let mut config = Config::for_host();
    config.toolchains.ios = Some(Ios {
        xcode_app: std::env::var_os("AGENTVAULT_TEST_XCODE_APP")
            .expect("explicit Xcode required")
            .into(),
    });
    let runtime = PathBuf::from(
        std::env::var_os("AGENTVAULT_TEST_SIMULATOR_RUNTIME").expect("explicit runtime required"),
    );
    let services =
        if std::env::var("AGENTVAULT_TEST_COMPILER_SIMULATOR_SERVICES").as_deref() == Ok("1") {
            SimulatorServices::Enabled
        } else {
            SimulatorServices::Restricted
        };
    let execute = |stage: &str, job: &Job, files: &Files| {
        println!("Starting native asset stage: {stage}");
        execute_with_services(
            project.path(),
            &config,
            &runtime,
            job,
            files,
            &AtomicBool::new(false),
            services,
        )
        .unwrap_or_else(|error| panic!("native asset stage {stage} failed:\n{error:#}"))
    };
    let version = execute(
        "version",
        &Job::AssetVersion {
            format: Format::Xml,
        },
        &Files::new(),
    );
    assert!(
        String::from_utf8_lossy(&version.stdout).contains("com.apple.actool.version"),
        "{}",
        String::from_utf8_lossy(&version.stdout)
    );
    let mut tagged = fixture::files();
    tagged.insert(
        "Assets.xcassets/Tagged.imageset/Contents.json".into(),
        br#"{"images":[{"filename":"Icon.png","idiom":"universal"}],"info":{"author":"xcode","version":1},"properties":{"on-demand-resource-tags":["FixtureTag"]}}"#.to_vec(),
    );
    tagged.insert(
        "Assets.xcassets/Tagged.imageset/Icon.png".into(),
        tagged[Path::new("Assets.xcassets/AppIcon.appiconset/Icon.png")].clone(),
    );
    let tags = execute(
        "asset tag query",
        &Job::AssetTagCombinations {
            catalogs: vec!["Assets.xcassets".into()],
        },
        &tagged,
    );
    assert!(tags.files.is_empty());
    let xml = String::from_utf8_lossy(&tags.stdout);
    assert!(
        xml.contains("com.apple.actool.asset-tag-combinations"),
        "{xml}"
    );
    assert!(xml.contains("<string>FixtureTag</string>"), "{xml}");
    let options = Options {
        app_icon: Some("AppIcon".into()),
        development_region: Some("en".into()),
        compress_pngs: true,
        on_demand_resources: true,
        partial_info: true,
        dependencies: true,
        ..Options::default()
    };
    let compiled = execute(
        "catalog compilation",
        &Job::AssetCatalog {
            catalogs: vec!["Assets.xcassets".into()],
            options: options.clone(),
        },
        &fixture::files(),
    );
    assert!(
        compiled
            .files
            .get(Path::new("Outputs/Assets.car"))
            .is_some_and(|b| !b.is_empty()),
        "{:?}",
        compiled.files.keys().collect::<Vec<_>>()
    );
    assert!(
        compiled
            .files
            .keys()
            .any(|p| p.extension().is_some_and(|s| s == "png")),
        "app icon must be compiled"
    );
    assert!(compiled.files.contains_key(Path::new("Aux/partial.plist")));
    let mappings = vec![
        (
            "Inputs/Assets.xcassets".into(),
            PathBuf::from("/copy/Assets.xcassets"),
        ),
        (
            "Aux/partial.plist".into(),
            PathBuf::from("/build/Assets.plist"),
        ),
    ];
    let remapped = agentvault::ib_bridge::client::remap_dependencies(
        &compiled.files[Path::new("Aux/dependencies")],
        &compiled.stage_root,
        &mappings,
        Path::new("/build/App.app"),
    )
    .unwrap();
    assert!(!remapped
        .windows(compiled.stage_root.len())
        .any(|b| b == compiled.stage_root.as_bytes()));
    let symbols = execute(
        "symbol generation",
        &Job::AssetCatalog {
            catalogs: vec!["Assets.xcassets".into()],
            options: Options {
                swift_symbols: true,
                objc_symbols: true,
                symbol_index: true,
                swift_extensions: Some(false),
                bundle_identifier: Some("dev.agentvault.Fixture".into()),
                ..options
            },
        },
        &fixture::files(),
    );
    for name in [
        "Aux/asset-symbols.swift",
        "Aux/asset-symbols.h",
        "Aux/asset-symbol-index.plist",
        "Aux/partial.plist",
        "Aux/dependencies",
    ] {
        assert!(
            symbols.files.contains_key(Path::new(name)),
            "{name}; {:?}",
            symbols.files.keys().collect::<Vec<_>>()
        );
    }
    assert!(
        String::from_utf8_lossy(&symbols.files[Path::new("Aux/asset-symbols.swift")])
            .contains("FixtureAccent")
    );
    println!("Verified actual actool version, Simulator Assets.car, app icon, partial metadata, dependencies, and Swift/Objective-C asset symbols in the constrained compiler.");
}
