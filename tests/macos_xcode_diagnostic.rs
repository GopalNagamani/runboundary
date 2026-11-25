//! Opt-in workspace discovery diagnostic; never builds a user project.
#![cfg(target_os = "macos")]
use runboundary::{
    policy::{config::Config, matcher::Matcher, toolchains::Ios},
    sandbox::{backend::Backend, process},
    security::paths::Dir,
    workspace::prepare,
};
use std::process::Command;

#[path = "support/macos_diagnostic.rs"]
mod diagnostic;
use diagnostic::{candidate_command, capture};

#[test]
#[ignore = "REAL Xcode diagnostic: explicit Xcode bundle approval and Terminal required"]
fn diagnose_workspace_discovery() {
    let app = std::env::var_os("RUNBOUNDARY_TEST_XCODE_APP")
        .expect("explicit RUNBOUNDARY_TEST_XCODE_APP approval required");
    let project = tempfile::tempdir().unwrap();
    let workspace = project.path().join("Synthetic.xcworkspace");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::write(
        workspace.join("contents.xcworkspacedata"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Workspace version=\"1.0\"></Workspace>\n",
    )
    .unwrap();
    let mut config = Config::for_host();
    config.toolchains.ios = Some(Ios {
        xcode_app: app.into(),
    });
    let backend = Backend::select(project.path(), &config).unwrap();
    let work = prepare::prepare(
        &Dir::open(project.path()).unwrap(),
        &Matcher::new(&config).unwrap(),
    )
    .unwrap();
    let env = backend.environment(&config, &[], work.path()).unwrap();
    backend.probe(project.path(), work.path(), &env).unwrap();
    let executable = backend.resolve("xcodebuild").unwrap();
    let args: Vec<String> = ["-list", "-json", "-workspace", "Synthetic.xcworkspace"]
        .map(String::from)
        .into();
    // Fixed empty workspace, no targets, build phases, signing or model calls.
    // Use separate homes and copied workspaces for host and sandbox controls.
    let host_work = prepare::prepare(
        &Dir::open(project.path()).unwrap(),
        &Matcher::new(&config).unwrap(),
    )
    .unwrap();
    let host_env = backend.environment(&config, &[], host_work.path()).unwrap();
    let mut host = Command::new(&executable);
    host.env_clear()
        .envs(&host_env)
        .current_dir(host_work.path())
        .args(&args);
    process::harden(&mut host);
    let (_, host_ok) = capture("host-clean-environment/relative-workspace", host);
    backend
        .cleanup_private_dirs(host_work.path(), &host_env)
        .unwrap();
    let command = backend
        .command(project.path(), work.path(), &env, &executable, &args)
        .unwrap();
    let (pid, sandbox_ok) = capture("production-profile/relative-workspace", command);
    let absolute_args = vec![
        "-list".into(),
        "-json".into(),
        "-workspace".into(),
        work.path()
            .join("Synthetic.xcworkspace")
            .to_str()
            .unwrap()
            .into(),
    ];
    let command = backend
        .command(
            project.path(),
            work.path(),
            &env,
            &executable,
            &absolute_args,
        )
        .unwrap();
    let (absolute_pid, absolute_ok) = capture("production-profile/absolute-workspace", command);
    backend.cleanup_private_dirs(work.path(), &env).unwrap();
    let mut pids = vec![pid, absolute_pid];
    let services = "(allow mach-lookup (global-name \"com.apple.CoreServices.coreservicesd\"))";
    let account = "(allow file-read* (literal \"/private/etc/passwd\") (literal \"/etc/passwd\"))";
    let combined = format!("{services}\n{account}");
    let mut successful = Vec::new();
    for (label, rules) in [
        ("core-services-only", services),
        ("local-account-record-only", account),
        ("core-services-and-account-record", combined.as_str()),
    ] {
        let candidate_work = prepare::prepare(
            &Dir::open(project.path()).unwrap(),
            &Matcher::new(&config).unwrap(),
        )
        .unwrap();
        let candidate_env = backend
            .environment(&config, &[], candidate_work.path())
            .unwrap();
        let base = backend
            .command(
                project.path(),
                candidate_work.path(),
                &candidate_env,
                &executable,
                &args,
            )
            .unwrap();
        let (pid, ok) = capture(label, candidate_command(&base, rules));
        pids.push(pid);
        if ok {
            successful.push(label);
        }
        backend
            .cleanup_private_dirs(candidate_work.path(), &candidate_env)
            .unwrap();
    }
    println!("Successful diagnostic-only candidates: {successful:?}; production policy unchanged");
    let selected_pids = pids
        .iter()
        .map(|pid| format!("eventMessage CONTAINS \"({pid})\""))
        .collect::<Vec<_>>()
        .join(" OR ");
    let base_predicate = format!("(process == \"kernel\" OR process == \"sandboxd\" OR subsystem BEGINSWITH \"com.apple.sandbox\") AND ({selected_pids})");
    // Split categories so noisy account lookups cannot truncate service denials.
    // Omitted repeated metadata paths were captured in the original report.
    let mut logs_ok = true;
    for (label, filter) in [
        ("service-denials", "eventMessage CONTAINS \"mach-lookup\""),
        ("other-denials", "NOT (eventMessage CONTAINS \"mach-lookup\" OR eventMessage CONTAINS \"/private/etc/passwd\" OR eventMessage CONTAINS \"/System/Cryptexes/\" OR eventMessage CONTAINS \"/System/Volumes/Data\")"),
    ] {
        let predicate = format!("({base_predicate}) AND ({filter})");
        let mut logs = Command::new("/usr/bin/log");
        logs.env_clear().args([
        "show",
        "--last",
        "5m",
        "--style",
        "compact",
        "--info",
        "--debug",
        "--predicate",
        &predicate,
    ]);
        process::harden(&mut logs);
        let (_, ok) = capture(label, logs);
        logs_ok &= ok;
    }
    println!("Denial lookup available: {logs_ok}; absent records are not evidence of permission");
    assert!(
        host_ok,
        "synthetic host workspace discovery failed; no sandbox compatibility conclusion"
    );
    assert!(
        sandbox_ok && absolute_ok,
        "synthetic sandbox workspace discovery failed; production policy unchanged"
    );
}
