//! Opt-in service-mediated canary probe. Never reads real credentials.
#![cfg(target_os = "macos")]
use agentvault::{
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
use diagnostic::{candidate_command, capture};

const SPAWN_PROBE: &str = include_str!("support/simulator_spawn_probe.m");

fn unknown_session_rejected(value: &serde_json::Value) -> bool {
    value["accepted"] == false
        && value["error"] == true
        && value["domain"] == "com.apple.SimLaunchHostService.RequestError"
        && value["code"] == 3
        && value["description"]
            .as_str()
            .is_some_and(|text| text.contains("Bad or unknown session"))
}

#[test]
fn interrupted_service_is_not_unknown_session_rejection() {
    let rejected = serde_json::json!({"accepted": false, "error": true,
        "domain": "com.apple.SimLaunchHostService.RequestError", "code": 3,
        "description": "Bad or unknown session: C1F65EAF-F303-4CA7-AE56-5FE89A09F9DE"});
    assert!(unknown_session_rejected(&rejected));
    // The supplied session-creation result: this connection interruption alone
    // cannot distinguish an intentional assertion from any other service crash.
    let interrupted = serde_json::json!({"accepted": false, "error": true,
        "domain": "NSPOSIXErrorDomain", "code": 53,
        "description": "Software caused connection abort; Connection interrupted"});
    assert!(!unknown_session_rejected(&interrupted));
    for value in [
        serde_json::json!({"accepted": false, "error": true, "description": "Connection invalid"}),
        serde_json::Value::Null,
    ] {
        assert!(!unknown_session_rejected(&value));
    }
    for (field, replacement) in [
        ("accepted", serde_json::json!(true)),
        ("error", serde_json::json!(1)),
        ("code", serde_json::json!(53)),
        ("code", serde_json::json!("3")),
        ("domain", serde_json::json!("NSPOSIXErrorDomain")),
        ("description", serde_json::json!("Connection interrupted")),
    ] {
        let mut invalid = rejected.clone();
        invalid[field] = replacement;
        assert!(!unknown_session_rejected(&invalid), "invalid {field}");
    }
}

#[test]
fn simulator_spawn_probe_compiles_without_connecting_to_services() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("spawn.m");
    let executable = temp.path().join("spawn");
    std::fs::write(&source, SPAWN_PROBE).unwrap();
    let developer = if Path::new("/Applications/Xcode.app/Contents/Developer").is_dir() {
        Path::new("/Applications/Xcode.app/Contents/Developer")
    } else {
        Path::new("/Library/Developer/CommandLineTools")
    };
    compile(&source, &executable, developer, false);
    // No arguments takes the usage-error branch before dlopen or any RPC.
    assert_eq!(Command::new(executable).status().unwrap().code(), Some(64));
}

const PROBE: &str = r#"
#import <Foundation/Foundation.h>
#import <objc/message.h>
#include <dlfcn.h>
#include <stdio.h>
static NSDictionary *serviceReport(BOOL accepted, NSError *error) {
 BOOL signatureRejected = error && [[error domain] isEqualToString:NSPOSIXErrorDomain]
    && [error code] == 88
    && [[error localizedDescription] containsString:@"mapping process is a platform binary, but mapped file is not"];
 // C relational expressions box as integer NSNumber objects. Use the Boolean
 // constructor explicitly so JSON contains true/false, never 1/0.
 return @{ @"accepted": [NSNumber numberWithBool:accepted],
    @"error": [NSNumber numberWithBool:error != nil],
    @"nonplatform_signature_rejected": [NSNumber numberWithBool:signatureRejected] };
}
int main(int argc, char **argv) { @autoreleasepool {
 if (argc == 2 && !strcmp(argv[1], "serialization-self-test")) {
   NSError *signature = [NSError errorWithDomain:NSPOSIXErrorDomain code:88
     userInfo:@{NSLocalizedDescriptionKey:@"mapping process is a platform binary, but mapped file is not"}];
   NSError *generic = [NSError errorWithDomain:NSPOSIXErrorDomain code:88
     userInfo:@{NSLocalizedDescriptionKey:@"generic loader failure"}];
   NSDictionary *cases = @{ @"accepted":serviceReport(YES,nil),
     @"rejected":serviceReport(NO,signature), @"generic":serviceReport(NO,generic) };
   NSData *json = [NSJSONSerialization dataWithJSONObject:cases options:0 error:nil];
   if (!json) return 74;
   fwrite([json bytes], 1, [json length], stdout); return 0;
 }
 if (argc != 3 && argc != 4) return 64;
 void *framework = dlopen("/Library/Developer/PrivateFrameworks/CoreSimulator.framework/CoreSimulator", RTLD_LAZY | RTLD_LOCAL);
 if (!framework) { puts("framework-unavailable"); return 70; }
 if (!strcmp(argv[1], "direct")) {
   void *payload = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
   if (!payload) { puts("direct-payload-load-failed"); return 71; }
   dlclose(payload); return 0;
 }
 Class cls = NSClassFromString(@"SimLaunchHostConnection");
 SEL initSelector = NSSelectorFromString(@"initWithServiceName:");
 SEL loadSelector = NSSelectorFromString(@"loadLibLaunchAtURL:error:");
 if (!cls || ![cls instancesRespondToSelector:initSelector] || ![cls instancesRespondToSelector:loadSelector]) {
   puts("unsupported-private-service-api"); return 78;
 }
 id connection = ((id (*)(id, SEL, id))objc_msgSend)([cls alloc], initSelector, @"com.apple.CoreSimulator.SimLaunchHost-arm64");
 NSMethodSignature *signature = [connection methodSignatureForSelector:loadSelector];
 if (!signature || [signature numberOfArguments] != 4) { puts("unsupported-service-signature"); return 78; }
 const char *type = [signature methodReturnType];
 if (strcmp(type, "@") && strcmp(type, "B") && strcmp(type, "c") && strcmp(type, "v")) {
   puts("unsupported-service-return-type"); return 78;
 }
 NSURL *url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:argv[2]]];
 NSError *error = nil; NSError **errorPointer = &error;
 NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
 [invocation setTarget:connection]; [invocation setSelector:loadSelector];
 [invocation setArgument:&url atIndex:2]; [invocation setArgument:&errorPointer atIndex:3];
 @try { [invocation invoke]; }
 @catch (NSException *exception) { puts("service-request-exception"); return 72; }
 printf("service-request-returned; error=%s\n", error ? "true" : "false");
 NSError *detail = error;
 for (int depth = 0; detail && depth < 4; depth++) {
   printf("service-error[%d]: domain=%.256s; code=%ld; description=%.2048s\n",
      depth, [[detail domain] UTF8String], (long)[detail code], [[detail localizedDescription] UTF8String]);
   id underlying = [[detail userInfo] objectForKey:NSUnderlyingErrorKey];
   detail = [underlying isKindOfClass:[NSError class]] ? underlying : nil;
 }
 BOOL accepted = NO;
 if (!strcmp(type, "@")) { id result = nil; [invocation getReturnValue:&result]; accepted = result != nil; }
 else if (!strcmp(type, "B") || !strcmp(type, "c")) { unsigned char result = 0; [invocation getReturnValue:&result]; accepted = result != 0; }
 printf("service-result: accepted=%s; return-type=%.16s\n", accepted ? "true" : "false", type);
 if (argc == 4) {
   NSDictionary *report = serviceReport(accepted, error);
   NSData *json = [NSJSONSerialization dataWithJSONObject:report options:0 error:nil];
   if (!json || ![json writeToFile:[NSString stringWithUTF8String:argv[3]] atomically:YES]) {
     puts("cannot-write-service-result"); return 74;
   }
 }
 if (!strcmp(argv[1], "trusted-control")) return accepted && !error ? 0 : 73;
 // Do not infer execution from the RPC return. The controller independently
 // checks the constructor's synthetic marker, even after a rejected request.
 return 0;
} }
"#;

fn compile(source: &Path, output: &Path, developer: &Path, dylib: bool) {
    let private_temp = source.parent().unwrap().canonicalize().unwrap();
    let mut compiler = Command::new("/usr/bin/clang");
    compiler
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DEVELOPER_DIR", developer)
        .env("TMPDIR", &private_temp)
        .env("HOME", &private_temp)
        .env("CFFIXED_USER_HOME", &private_temp);
    if dylib {
        compiler.arg("-dynamiclib");
    } else {
        compiler.args(["-framework", "Foundation"]);
    }
    let result = compiler.arg(source).arg("-o").arg(output).output().unwrap();
    assert!(
        result.status.success(),
        "fixed synthetic probe compilation failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn foundation_report_uses_json_booleans_and_distinguishes_generic_errors() {
    // This is a native serializer regression, not a Simulator isolation test.
    // Compile the actual fixed helper and take its early self-test path: no
    // CoreSimulator framework load or service connection is attempted.
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("report.m");
    let executable = temp.path().join("report");
    std::fs::write(&source, PROBE).unwrap();
    let developer = if Path::new("/Applications/Xcode.app/Contents/Developer").is_dir() {
        Path::new("/Applications/Xcode.app/Contents/Developer")
    } else {
        Path::new("/Library/Developer/CommandLineTools")
    };
    compile(&source, &executable, developer, false);
    let output = Command::new(&executable)
        .env_clear()
        .env("HOME", temp.path())
        .env("CFFIXED_USER_HOME", temp.path())
        .arg("serialization-self-test")
        .output()
        .unwrap();
    assert!(output.status.success());
    let cases: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for name in ["accepted", "rejected", "generic"] {
        for field in ["accepted", "error", "nonplatform_signature_rejected"] {
            assert!(
                cases[name][field].is_boolean(),
                "{name}.{field} must be a JSON Boolean, not a boxed C integer"
            );
        }
    }
    assert_eq!(cases["accepted"]["accepted"], true);
    assert_eq!(cases["accepted"]["error"], false);
    assert_eq!(cases["rejected"]["nonplatform_signature_rejected"], true);
    assert_eq!(cases["rejected"]["error"], true);
    assert_eq!(cases["rejected"]["accepted"], false);
    assert_eq!(cases["generic"]["error"], true);
    assert_eq!(cases["generic"]["nonplatform_signature_rejected"], false);
}

fn approved_runtime() -> (PathBuf, PathBuf) {
    let runtime = PathBuf::from(std::env::var_os("AGENTVAULT_TEST_SIMULATOR_RUNTIME")
        .expect("explicit AGENTVAULT_TEST_SIMULATOR_RUNTIME approval required for the service positive control"))
        .canonicalize().expect("approved runtime must exist");
    assert!(
        runtime.starts_with("/Library/Developer/CoreSimulator/Volumes")
            && runtime.extension().and_then(|x| x.to_str()) == Some("simruntime")
    );
    let admin = unsafe { libc::getgrnam(c"admin".as_ptr()) };
    assert!(!admin.is_null());
    let admin_gid = unsafe { (*admin).gr_gid };
    for ancestor in runtime.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor).unwrap();
        assert!(
            meta.is_dir()
                && meta.uid() == 0
                && meta.mode() & 0o6002 == 0
                && (meta.mode() & 0o020 == 0 || meta.gid() == admin_gid),
            "approved runtime must be root/admin controlled"
        );
    }
    let trusted_library = runtime
        .join("Contents/Resources/RuntimeRoot/usr/lib/system/host/liblaunch_sim.dylib")
        .canonicalize()
        .unwrap();
    assert!(
        trusted_library.starts_with(&runtime) && trusted_library.is_file(),
        "approved runtime library must remain inside the runtime"
    );
    (runtime, trusted_library)
}

#[test]
#[ignore = "REAL unknown-session spawn test: explicit Xcode/runtime/helper approval; Terminal only"]
fn simulator_service_rejects_unknown_session_spawn() {
    assert_eq!(
        std::env::var("AGENTVAULT_TEST_ALLOW_SIMULATOR_SERVICES").as_deref(),
        Ok("1"),
        "explicit helper-connection approval required"
    );
    assert_eq!(std::env::consts::ARCH, "aarch64");
    let (runtime, trusted_library) = approved_runtime();
    let project = tempfile::tempdir().unwrap();
    let secret = project.path().join(".env");
    std::fs::write(&secret, b"SYNTHETIC_SERVICE_CANARY").unwrap();
    let mut config = Config::for_host();
    config.toolchains.ios = Some(Ios {
        xcode_app: std::env::var_os("AGENTVAULT_TEST_XCODE_APP")
            .expect("explicit Xcode approval required")
            .into(),
    });
    let backend = Backend::select(project.path(), &config).unwrap();
    let work = prepare::prepare(
        &Dir::open(project.path()).unwrap(),
        &Matcher::new(&config).unwrap(),
    )
    .unwrap();
    let env = backend.environment(&config, &[], work.path()).unwrap();
    // Do not make service requests when the production sandbox cannot start.
    backend.probe(project.path(), work.path(), &env).unwrap();
    let developer = Path::new(&env["DEVELOPER_DIR"]);
    let source = project.path().join("spawn.m");
    let executable = work.path().join("spawn-probe");
    std::fs::write(&source, SPAWN_PROBE).unwrap();
    compile(&source, &executable, developer, false);
    let payload_source = project.path().join("child.c");
    let payload = work.path().join("fixed-child");
    let marker = work.path().join("child-result");
    let code = r#"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
int main(void) {
 int input = open(@CANARY@, O_RDONLY | O_NOFOLLOW);
 int denied = input < 0 && (errno == EACCES || errno == EPERM);
 char bytes[32] = {0};
 ssize_t count = input < 0 ? -1 : read(input, bytes, sizeof(bytes));
 if (input >= 0) close(input);
 const char *result = count == 24 && !memcmp(bytes, "SYNTHETIC_SERVICE_CANARY", 24)
   ? "HOST_CANARY_READ" : denied ? "HOST_CANARY_DENIED" : "HOST_CANARY_ERROR";
 int output = open(@MARKER@, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
 if (output < 0) return 74;
 ssize_t written = write(output, result, strlen(result)); close(output);
 return written == (ssize_t)strlen(result) ? 0 : 74;
}
"#;
    let code = code
        .replace(
            "@CANARY@",
            &serde_json::to_string(secret.to_str().unwrap()).unwrap(),
        )
        .replace(
            "@MARKER@",
            &serde_json::to_string(marker.to_str().unwrap()).unwrap(),
        );
    std::fs::write(&payload_source, code).unwrap();
    compile(&payload_source, &payload, developer, false);
    let mut host = Command::new(&payload);
    host.env_clear().envs(&env).current_dir(work.path());
    process::harden(&mut host);
    assert!(capture("session-spawn/host-child-control", host).1);
    assert_eq!(std::fs::read(&marker).unwrap(), b"HOST_CANARY_READ");
    std::fs::remove_file(&marker).unwrap();
    let shell = backend.resolve("/bin/sh").unwrap();
    let command = |args: &[String]| {
        backend
            .preview_command(project.path(), work.path(), &env, &shell, args, false)
            .unwrap()
    };
    let direct = command(&["-c".into(), "exec ./fixed-child".into()]);
    assert!(capture("session-spawn/sandbox-child-control", direct).1);
    assert_eq!(std::fs::read(&marker).unwrap(), b"HOST_CANARY_DENIED");
    std::fs::remove_file(&marker).unwrap();
    let report = work.path().join("spawn-result.json");
    let args = [
        "-c".into(),
        "exec \"$@\"".into(),
        "session-spawn".into(),
        "./spawn-probe".into(),
        trusted_library.to_str().unwrap().into(),
        payload.to_str().unwrap().into(),
        report.to_str().unwrap().into(),
        marker.to_str().unwrap().into(),
    ];
    let candidate = diagnostic::candidate_with_parameters(&command(&args),
        "(allow mach-lookup (global-name \"com.apple.CoreSimulator.SimLaunchHost-arm64\"))\n(allow file-read* file-map-executable (subpath (param \"SERVICE_RUNTIME\")))",
        &[("SERVICE_RUNTIME", runtime.to_str().unwrap())]);
    let (_, completed) = capture("session-spawn/service-authorization", candidate);
    let output: Option<serde_json::Value> = std::fs::read(&report)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let child_marker = std::fs::read(&marker).ok();
    backend.cleanup_private_dirs(work.path(), &env).unwrap();
    println!("Session/spawn report: {output:?}; child marker: {child_marker:?}");
    assert!(
        completed,
        "INCONCLUSIVE: helper did not complete its trusted-library control and requests"
    );
    let output = output.expect("INCONCLUSIVE: no structured service report");
    assert_eq!(output["trusted_library_accepted"], true);
    assert_eq!(output["session_creation_attempted"], false);
    assert!(child_marker.is_none() && output["spawn"]["accepted"] != true,
        "UNSAFE CANDIDATE: service accepted or executed a child in an unowned session; do not enable this permission");
    assert!(unknown_session_rejected(&output["spawn"]),
        "INCONCLUSIVE: no explicit unknown-session rejection; executable/platform errors do not establish session ownership checks");
    println!("Verified only: this client cannot spawn in a fresh unknown session. No session creation was attempted. Existing-session ownership, alternate RPCs and full project builds remain unverified.");
}

#[test]
#[ignore = "REAL service canary experiment: explicit Xcode and helper approval; Apple silicon Terminal only"]
fn simulator_service_rejects_nonplatform_library() {
    assert_eq!(
        std::env::var("AGENTVAULT_TEST_ALLOW_SIMULATOR_SERVICES").as_deref(),
        Ok("1"),
        "explicit helper-connection approval required"
    );
    assert_eq!(std::env::consts::ARCH, "aarch64");
    let (runtime, trusted_library) = approved_runtime();
    let project = tempfile::tempdir().unwrap();
    let secret = project.path().join(".env");
    std::fs::write(&secret, b"SYNTHETIC_SERVICE_CANARY").unwrap();
    let mut config = Config::for_host();
    config.toolchains.ios = Some(Ios {
        xcode_app: std::env::var_os("AGENTVAULT_TEST_XCODE_APP")
            .expect("explicit Xcode approval required")
            .into(),
    });
    let backend = Backend::select(project.path(), &config).unwrap();
    let work = prepare::prepare(
        &Dir::open(project.path()).unwrap(),
        &Matcher::new(&config).unwrap(),
    )
    .unwrap();
    let env = backend.environment(&config, &[], work.path()).unwrap();
    backend.probe(project.path(), work.path(), &env).unwrap();
    let developer = Path::new(&env["DEVELOPER_DIR"]);
    let source = project.path().join("probe.m");
    std::fs::write(&source, PROBE).unwrap();
    let executable = work.path().join("service-probe");
    compile(&source, &executable, developer, false);
    let marker = work.path().join("constructor-result");
    let payload_source = project.path().join("payload.c");
    let code = r#"
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
__attribute__((constructor)) static void probe(void) {
 int input = open(@CANARY@, O_RDONLY | O_NOFOLLOW);
 char bytes[32] = {0};
 ssize_t count = input < 0 ? -1 : read(input, bytes, sizeof(bytes));
 if (input >= 0) close(input);
 const char *result = count == 24 && !memcmp(bytes, "SYNTHETIC_SERVICE_CANARY", 24)
   ? "HOST_CANARY_READ" : "HOST_CANARY_DENIED";
 int output = open(@MARKER@, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
 if (output >= 0) { write(output, result, strlen(result)); close(output); }
}
"#;
    let code = code
        .replace(
            "@CANARY@",
            &serde_json::to_string(secret.to_str().unwrap()).unwrap(),
        )
        .replace(
            "@MARKER@",
            &serde_json::to_string(marker.to_str().unwrap()).unwrap(),
        );
    std::fs::write(&payload_source, code).unwrap();
    let payload = work.path().join("liblaunch_sim.dylib");
    compile(&payload_source, &payload, developer, true);
    let report_path = work.path().join("service-result.json");
    let args = |mode: &str| {
        vec![
            "-c".into(),
            "exec \"$@\"".into(),
            "service-canary".into(),
            "./service-probe".into(),
            mode.into(),
            payload.to_str().unwrap().into(),
            report_path.to_str().unwrap().into(),
        ]
    };
    let mut host = Command::new(&executable);
    host.env_clear()
        .envs(&env)
        .current_dir(work.path())
        .arg("direct")
        .arg(&payload);
    process::harden(&mut host);
    let (_, host_ok) = capture("constructor/host-direct-control", host);
    assert!(host_ok);
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        b"HOST_CANARY_READ",
        "host synthetic payload control failed"
    );
    std::fs::remove_file(&marker).unwrap();
    let shell = backend.resolve("/bin/sh").unwrap();
    // Positive control: prove this client can ask the service to load the
    // selected real Apple library before drawing conclusions from a fake one.
    let trusted_args = vec![
        "-c".into(),
        "exec \"$@\"".into(),
        "trusted-library-control".into(),
        "./service-probe".into(),
        "trusted-control".into(),
        trusted_library.to_str().unwrap().into(),
    ];
    let base = backend
        .preview_command(
            project.path(),
            work.path(),
            &env,
            &shell,
            &trusted_args,
            false,
        )
        .unwrap();
    let positive = diagnostic::candidate_with_parameters(&base,
        "(allow mach-lookup (global-name \"com.apple.CoreSimulator.SimLaunchHost-arm64\"))\n(allow file-read* file-map-executable (subpath (param \"SERVICE_RUNTIME\")))",
        &[("SERVICE_RUNTIME", runtime.to_str().unwrap())]);
    let (_, service_control_ok) = capture("constructor/approved-Apple-library-control", positive);
    let direct = backend
        .preview_command(
            project.path(),
            work.path(),
            &env,
            &shell,
            &args("direct"),
            false,
        )
        .unwrap();
    let (_, direct_ok) = capture("constructor/sandbox-direct-control", direct);
    assert!(direct_ok);
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        b"HOST_CANARY_DENIED",
        "direct sandbox synthetic canary access was not denied"
    );
    std::fs::remove_file(&marker).unwrap();
    let base = backend
        .preview_command(
            project.path(),
            work.path(),
            &env,
            &shell,
            &args("service"),
            false,
        )
        .unwrap();
    let (_, request_ok) = capture(
        "constructor/service-mediated-request",
        candidate_command(
            &base,
            "(allow mach-lookup (global-name \"com.apple.CoreSimulator.SimLaunchHost-arm64\"))",
        ),
    );
    let result = std::fs::read(&marker).ok();
    let report: Option<serde_json::Value> = std::fs::read(&report_path)
        .ok()
        .and_then(|data| serde_json::from_slice(&data).ok());
    for field in ["accepted", "error", "nonplatform_signature_rejected"] {
        println!(
            "Service result {field}: {:?}",
            report.as_ref().and_then(|value| value[field].as_bool())
        );
    }
    backend.cleanup_private_dirs(work.path(), &env).unwrap();
    match result.as_deref() {
        Some(b"HOST_CANARY_READ") => panic!("UNSAFE CANDIDATE: the service-loaded constructor read the synthetic host canary. Do not promote this helper permission"),
        Some(b"HOST_CANARY_DENIED") => panic!("Test library executed with canary access denied, but this test specifically requires non-platform library rejection; helper spawning remains unverified"),
        None if service_control_ok && request_ok && report.as_ref().is_some_and(|value|
            value["accepted"] == false && value["error"] == true
            && value["nonplatform_signature_rejected"] == true) => {
                println!("Verified this operation: approved Apple runtime accepted; synthetic non-platform library rejected by code-signing enforcement before its constructor ran. This does not verify helper-spawned process confinement.");
            }
        _ => panic!("INCONCLUSIVE SERVICE TEST: Apple-library-control={service_control_ok}, payload-request-returned={request_ok}; neither execution nor the specific platform-signature rejection was established. No complete service-confinement claim"),
    }
}
