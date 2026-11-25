//! Opt-in real Xcode compatibility test. Never accepts a license or runs sudo.
#![cfg(target_os = "macos")]
use runboundary::{
    policy::{config::Config, matcher::Matcher, toolchains::Ios},
    sandbox::{backend::Backend, process},
    security::paths::Dir,
    workspace::prepare,
};
use std::{
    path::Path,
    process::{Command, Stdio},
};

#[test]
#[ignore = "REAL Xcode test: explicitly set RUNBOUNDARY_TEST_XCODE_APP; accepted host license required"]
fn accepted_xcode_license_is_visible_read_only_without_host_user_preferences() {
    let app = std::env::var_os("RUNBOUNDARY_TEST_XCODE_APP").expect(
        "set RUNBOUNDARY_TEST_XCODE_APP to explicitly approve Xcode; no automatic SDK import",
    );
    let root = tempfile::tempdir().unwrap();
    let mut config = Config::for_host();
    config.toolchains.ios = Some(Ios {
        xcode_app: app.into(),
    });
    let backend = Backend::select(root.path(), &config).unwrap();
    let executable = backend.resolve("xcodebuild").unwrap();
    let host = Command::new(&executable)
        .args(["-license", "check"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(host.success(),"host Xcode license check failed; complete Xcode setup manually. RunBoundary did not accept any license");
    let synthetic = root.path().join("Synthetic.xcworkspace");
    std::fs::create_dir(&synthetic).unwrap();
    std::fs::write(
        synthetic.join("contents.xcworkspacedata"),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Workspace version=\"1.0\"></Workspace>\n",
    )
    .unwrap();
    let matcher = Matcher::new(&config).unwrap();
    let work = prepare::prepare(&Dir::open(root.path()).unwrap(), &matcher).unwrap();
    let env = backend.environment(&config, &[], work.path()).unwrap();
    backend.probe(root.path(), work.path(), &env).unwrap();
    let record = runboundary::sandbox::seatbelt::XCODE_LICENSE_RECORD;
    let mut cmd = backend
        .command(
            root.path(),
            work.path(),
            &env,
            &executable,
            &["-license".into(), "check".into()],
        )
        .unwrap();
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    assert!(
        process::interactive(&mut cmd).unwrap().success(),
        "sandbox cannot observe accepted Xcode license; no license was accepted or modified"
    );
    let host_canary = tempfile::NamedTempFile::new().unwrap();
    let args = vec![
        "-c".into(),
        r#"set -eu
/bin/cat "$1" >/dev/null
[ ! -w "$1" ]
! /bin/cat "$2" >/dev/null 2>&1
"#
        .into(),
        "license-probe".into(),
        record.into(),
        host_canary.path().to_str().unwrap().into(),
    ];
    let output = backend
        .command(
            root.path(),
            work.path(),
            &env,
            &backend.resolve("/bin/sh").unwrap(),
            &args,
        )
        .unwrap()
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "license record readonly/host-canary isolation check failed"
    );
    // Compile only this fixed synthetic helper on the host, then execute the
    // copied binary exclusively inside the sandbox. No project scripts run here.
    let source = root.path().join("framework-probe.m");
    std::fs::write(&source, r#"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#import <Foundation/Foundation.h>
int main(void) {
    @autoreleasepool {
        const char *home = getenv("HOME");
        const char *fixed = getenv("CFFIXED_USER_HOME");
        NSString *actual = NSHomeDirectory();
        struct stat expectedStat, actualStat;
        // Cocoa may normalize a system path alias. Require the same existing
        // directory, not merely a matching string or a shared path prefix.
        if (!home || !fixed || strcmp(home, fixed) != 0 ||
            stat(home, &expectedStat) != 0 || !S_ISDIR(expectedStat.st_mode) ||
            stat([actual fileSystemRepresentation], &actualStat) != 0 ||
            !S_ISDIR(actualStat.st_mode) ||
            expectedStat.st_dev != actualStat.st_dev ||
            expectedStat.st_ino != actualStat.st_ino) {
            fprintf(stderr, "Cocoa home differs from private HOME: HOME=%s; CFFIXED_USER_HOME=%s; Cocoa=%s\n",
                home ? home : "[missing]", fixed ? fixed : "[missing]",
                actual ? [actual fileSystemRepresentation] : "[missing]");
            return 2;
        }
    }
    void *framework = dlopen("/Library/Developer/PrivateFrameworks/CoreSimulator.framework/CoreSimulator", RTLD_LAZY | RTLD_LOCAL);
    if (!framework) { fprintf(stderr, "%s\n", dlerror()); return 1; }
    dlclose(framework);
    return 0;
}
"#).unwrap();
    let binary = work.path().join("framework-probe");
    let compilation = Command::new("/usr/bin/clang")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(
            "DEVELOPER_DIR",
            executable
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
        )
        .arg(&source)
        .args(["-framework", "Foundation"])
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compilation.status.success(),
        "synthetic framework probe compilation failed: {}",
        String::from_utf8_lossy(&compilation.stderr)
    );
    let output = backend
        .preview_command(
            root.path(),
            work.path(),
            &env,
            &backend.resolve("/bin/sh").unwrap(),
            &["-c".into(), "exec ./framework-probe".into()],
            false,
        )
        .unwrap()
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sandbox CoreSimulator framework load failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Regression: loading frameworks alone did not prove that Xcode could
    // recognize even an empty, valid workspace with no targets/build scripts.
    let output = backend
        .command(
            root.path(),
            work.path(),
            &env,
            &executable,
            &[
                "-list".into(),
                "-json".into(),
                "-workspace".into(),
                "Synthetic.xcworkspace".into(),
            ],
        )
        .unwrap()
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "sandbox synthetic workspace discovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let discovered: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("Xcode workspace discovery must return JSON");
    assert_eq!(discovered["workspace"]["name"], "Synthetic");
    backend.cleanup_private_dirs(work.path(), &env).unwrap();
    // Negative control: a normal profile does not gain this system-record read.
    let normal = Config::for_host();
    let plain_backend = Backend::select(root.path(), &normal).unwrap();
    let plain_work = prepare::prepare(&Dir::open(root.path()).unwrap(), &matcher).unwrap();
    let plain_env = plain_backend
        .environment(&normal, &[], plain_work.path())
        .unwrap();
    let args = vec![
        "-c".into(),
        "! /bin/cat \"$1\" >/dev/null 2>&1 && ! /bin/cat \"$2/CoreSimulator\" >/dev/null 2>&1"
            .into(),
        "unapproved-probe".into(),
        record.into(),
        runboundary::sandbox::seatbelt::XCODE_CORE_SIMULATOR.into(),
    ];
    let output = plain_backend
        .command(
            root.path(),
            plain_work.path(),
            &plain_env,
            &plain_backend.resolve("/bin/sh").unwrap(),
            &args,
        )
        .unwrap()
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "unselected Xcode license record unexpectedly readable"
    );
    assert!(Path::new(record).is_file());
}
