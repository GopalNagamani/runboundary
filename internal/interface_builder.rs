//! Narrow, developer-invoked XIB compilation. No arbitrary command/IPC proxy.
pub mod assets;
pub mod build;
use crate::{
    policy::config::Config,
    sandbox::{backend::Backend, process},
    security::paths::Dir,
};
use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub const INPUT_LIMIT: u64 = 8 * 1024 * 1024;
const OUTPUT_LIMIT: usize = 64 * 1024 * 1024;
const FILE_COUNT_LIMIT: usize = 4096;
const LOG_LIMIT: usize = 64 * 1024;

pub struct Request {
    pub source: Vec<u8>,
    pub module: Option<String>,
    pub deployment_target: String,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        if self.source.is_empty() || self.source.len() as u64 > INPUT_LIMIT {
            bail!("XIB input must be nonempty and at most 8 MiB");
        }
        let text = std::str::from_utf8(&self.source).context("XIB must be UTF-8")?;
        if text.contains('\0')
            || text.to_ascii_uppercase().contains("<!DOCTYPE")
            || text.to_ascii_uppercase().contains("<!ENTITY")
        {
            bail!("XIB document types, external entities and NUL bytes are unsupported");
        }
        if let Some(module) = &self.module {
            if module.is_empty()
                || module.len() > 128
                || !module.bytes().enumerate().all(|(i, b)| {
                    b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                })
            {
                bail!("module must be a simple identifier, at most 128 bytes");
            }
        }
        let parts: Vec<_> = self.deployment_target.split('.').collect();
        if !(2..=3).contains(&parts.len())
            || parts.iter().any(|part| {
                part.is_empty()
                    || part.len() > 3
                    || !part.bytes().all(|b| b.is_ascii_digit())
                    || part.parse::<u16>().map_or(true, |n| n > 255)
            })
        {
            bail!("deployment target must be a numeric version such as 17.2");
        }
        Ok(())
    }
    fn arguments(&self) -> Vec<String> {
        let mut args: Vec<String> = [
            "--errors",
            "--warnings",
            "--notices",
            "--target-device",
            "iphone",
            "--target-device",
            "ipad",
            "--minimum-deployment-target",
        ]
        .map(String::from)
        .into();
        args.push(self.deployment_target.clone());
        if let Some(module) = &self.module {
            args.extend(["--module".into(), module.clone()]);
        }
        args.extend(
            [
                "--output-format",
                "human-readable-text",
                "--compile",
                "Compiled.nib",
                "Input.xib",
            ]
            .map(String::from),
        );
        args
    }
}

pub struct Artifact {
    pub directory: bool,
    pub files: BTreeMap<PathBuf, Vec<u8>>,
}
impl Artifact {
    /// Export only immutable bytes. The compiler's directories are never moved
    /// into the retained session and cannot race publication after validation.
    pub fn read(root: &Dir) -> Result<Self> {
        Self::read_named(root, OsStr::new("Compiled.nib"))
    }
    pub(crate) fn read_named(root: &Dir, name: &OsStr) -> Result<Self> {
        let meta = root.metadata(name)?;
        let mut files = BTreeMap::new();
        let mut total = 0;
        let mut nodes = 0;
        if meta.directory() {
            let child = root.child(name)?;
            read_tree(&child, Path::new(""), &mut files, &mut total, &mut nodes)?;
        } else if meta.regular() {
            let bytes = root.read_file(Path::new(name), OUTPUT_LIMIT as u64)?.0;
            total = bytes.len();
            files.insert(PathBuf::new(), bytes);
        } else {
            bail!("compiler output must be a regular NIB file or directory");
        }
        if total == 0 {
            bail!("compiler returned an empty artifact");
        }
        Ok(Self {
            directory: meta.directory(),
            files,
        })
    }
    pub fn publish(
        &self,
        workspace: &Path,
        output: &Path,
        matcher: &crate::policy::matcher::Matcher,
    ) -> Result<()> {
        validate_relative(output, "nib")?;
        self.publish_path(workspace, output, matcher)
    }
    pub(crate) fn publish_path(
        &self,
        workspace: &Path,
        output: &Path,
        matcher: &crate::policy::matcher::Matcher,
    ) -> Result<()> {
        validate_relative_file(output)?;
        if matcher.protected(output) {
            bail!("protected output path");
        }
        for name in self.files.keys() {
            if !name.as_os_str().is_empty() {
                validate_relative_file(name)?;
            }
            if matcher.protected(&output.join(name)) {
                bail!("protected compiler output rejected");
            }
        }
        let destination = Dir::open(workspace)?;
        // Pin an existing no-follow parent before staging. Never create parents
        // chosen by the compiler or follow an output-directory link.
        let (parent, name) = destination.parent(output)?;
        let staging = tempfile::Builder::new()
            .prefix("agentvault-nib-publish-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(workspace.parent().context("missing session parent")?)?;
        let staged = Dir::open(staging.path())?;
        if self.directory {
            staged.mkdir(OsStr::new("artifact"))?;
            let artifact = staged.child(OsStr::new("artifact"))?;
            for (path, bytes) in &self.files {
                artifact.ensure_parent(path)?;
                artifact.create(path, bytes, 0o600)?;
            }
        } else {
            staged.create(
                Path::new("artifact"),
                self.files
                    .get(Path::new(""))
                    .context("missing flat artifact")?,
                0o600,
            )?;
        }
        staged
            .rename(Path::new("artifact"), &parent, Path::new(&name))
            .context("cannot publish NIB: output must not already exist")?;
        Ok(())
    }
}
fn read_tree(
    root: &Dir,
    prefix: &Path,
    files: &mut BTreeMap<PathBuf, Vec<u8>>,
    total: &mut usize,
    nodes: &mut usize,
) -> Result<()> {
    if prefix.components().count() > 32 {
        bail!("compiler output nesting limit exceeded");
    }
    let names = root.entries()?;
    // Reserve all entries before recursion so wide sibling directories cannot
    // accumulate unbounded pending traversal state, including empty directories.
    *nodes += names.len();
    if *nodes > FILE_COUNT_LIMIT {
        bail!("compiler output entry-count limit exceeded");
    }
    for name in names {
        let path = prefix.join(&name);
        validate_relative_file(&path)?;
        let meta = root.metadata(name.as_os_str())?;
        if meta.directory() {
            read_tree(&root.child(name.as_os_str())?, &path, files, total, nodes)?;
        } else {
            if files.len() >= FILE_COUNT_LIMIT {
                bail!("compiler output file-count limit exceeded");
            }
            let bytes = root.read_file(&name, (OUTPUT_LIMIT - *total) as u64)?.0;
            *total += bytes.len();
            files.insert(path, bytes);
        }
    }
    Ok(())
}
pub fn validate_relative(path: &Path, extension: &str) -> Result<()> {
    validate_relative_file(path)?;
    if path.extension() != Some(OsStr::new(extension)) {
        bail!("expected a .{extension} path");
    }
    Ok(())
}
pub(crate) fn validate_relative_file(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.components().count() > 32
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("expected a bounded workspace-relative path without traversal");
    }
    Ok(())
}

pub struct Compilation {
    pub artifact: Artifact,
    pub diagnostics: Vec<u8>,
}

pub fn compile(
    project: &Path,
    config: &Config,
    runtime: &Path,
    request: &Request,
) -> Result<Compilation> {
    request.validate()?;
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        bail!("experimental XIB broker requires an unprivileged Apple silicon Mac");
    }
    let ios = config
        .toolchains
        .ios
        .as_ref()
        .context("configure an explicitly approved Xcode toolchain first")?;
    // A compiler needs only Xcode. Do not import other approved agent runtimes,
    // SDKs, caches or environment customizations into the separate boundary.
    let mut compiler_config = Config::for_host();
    compiler_config.toolchains.ios = Some(crate::policy::toolchains::Ios {
        xcode_app: ios.xcode_app.clone(),
    });
    let runtime = approve_runtime(runtime)?;
    let backend = Backend::select(project, &compiler_config)?;
    let compiler = backend.resolve("ibtoold")?;
    let temp = tempfile::Builder::new()
        .prefix("agentvault-xib-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let work = temp.path().join("workspace");
    Dir::open(temp.path())?.mkdir(OsStr::new("workspace"))?;
    let work = work.canonicalize()?;
    let staged = Dir::open(&work)?;
    staged.create(Path::new("Input.xib"), &request.source, 0o600)?;
    let mut env = backend.environment(&compiler_config, &[], &work)?;
    // Ensure the main sandbox's proven boundary starts before any helper RPC.
    backend.probe(project, &work, &env)?;
    let catalog = Path::new(&env["HOME"]).join("Library/Developer/CoreSimulator/Profiles/Runtimes");
    std::fs::create_dir_all(&catalog)?;
    std::os::unix::fs::symlink(
        &runtime,
        catalog.join(runtime.file_name().context("runtime has no name")?),
    )?;
    env.insert("IBToolNeverDeque".into(), "1".into());
    let base =
        backend.offline_compiler_command(project, &work, &env, &compiler, &request.arguments())?;
    let command = compiler_access(&base, &runtime)?;
    let output = capture(command, Duration::from_secs(60))?;
    if !output.success {
        bail!(
            "sandboxed XIB compilation failed: {}",
            String::from_utf8_lossy(&output.diagnostics).escape_debug()
        );
    }
    let artifact = Artifact::read(&staged)?;
    // temp also drops homes/caches. Only validated artifact bytes leave it.
    Ok(Compilation {
        artifact,
        diagnostics: output.diagnostics,
    })
}

pub(crate) fn approve_runtime(runtime: &Path) -> Result<PathBuf> {
    if !runtime.is_absolute() {
        bail!("runtime approval must be an absolute path");
    }
    let path = runtime.canonicalize()?;
    if !path.starts_with("/Library/Developer/CoreSimulator/Volumes")
        || path.extension() != Some(OsStr::new("simruntime"))
        || !path.join("Contents/Resources/RuntimeRoot").is_dir()
    {
        bail!("approve one installed system Simulator runtime bundle");
    }
    trusted_directory(&path)?;
    Ok(path)
}
fn trusted_directory(path: &Path) -> Result<()> {
    let group = unsafe { libc::getgrnam(c"admin".as_ptr()) };
    if group.is_null() {
        bail!("macOS administrator group unavailable");
    }
    let admin = unsafe { (*group).gr_gid };
    for ancestor in path.ancestors() {
        let m = std::fs::symlink_metadata(ancestor)?;
        if !m.is_dir()
            || m.uid() != 0
            || m.mode() & 0o6002 != 0
            || (m.mode() & 0o020 != 0 && m.gid() != admin)
        {
            bail!("SDK/runtime directories must be real root/admin-controlled directories");
        }
    }
    Ok(())
}

const COMPILER_RULES: &str = r#"
; Only the isolated fixed compiler receives this endpoint. No agent/build scripts.
(allow mach-lookup (global-name "com.apple.CoreSimulator.SimLaunchHost-arm64"))
(allow file-read* file-map-executable
 (subpath (param "IB_RUNTIME")) (subpath (param "IB_DEVICE_TYPES")) (subpath (param "IB_DEVICE_KIT")))
(allow file-read* (literal "/Library") (literal "/Library/Developer")
 (literal "/Library/Developer/CoreSimulator") (literal "/Library/Developer/CoreSimulator/Profiles"))
; Network grants are omitted by Backend::offline_compiler_command.
"#;

/// Host-selected authority; never deserialized from an untrusted bridge job.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SimulatorServices {
    #[default]
    Restricted,
    /// Explicit developer opt-in: Apple services can use host account authority.
    Enabled,
}

fn compiler_profile(source: &str, services: SimulatorServices) -> Result<String> {
    let source = source
        .strip_suffix("\n(deny process-info*)\n")
        .context("missing final process isolation rule")?;
    let services = match services {
        SimulatorServices::Restricted => {
            r#"
(deny mach-lookup
 (global-name "com.apple.CoreSimulator.CoreSimulatorService")
 (global-name "com.apple.CoreSimulator.CoreSimulatorService.xpc")
 (global-name "com.apple.CoreSimulator.simdiskimaged"))
"#
        }
        SimulatorServices::Enabled => {
            r#"
; Compiler-only compatibility opt-in. Shared services are trusted host components.
(allow mach-lookup
 (global-name "com.apple.CoreSimulator.CoreSimulatorService")
 (global-name "com.apple.CoreSimulator.CoreSimulatorService.xpc")
 (xpc-service-name "com.apple.CoreSimulator.CoreSimulatorService")
 (global-name "com.apple.CoreSimulator.simdiskimaged"))
"#
        }
    };
    Ok(format!(
        "{source}\n{COMPILER_RULES}\n{services}\n(deny process-info*)\n"
    ))
}

fn compiler_access(base: &Command, runtime: &Path) -> Result<Command> {
    compiler_access_with_services(base, runtime, SimulatorServices::Restricted)
}

fn compiler_access_with_services(
    base: &Command,
    runtime: &Path,
    services: SimulatorServices,
) -> Result<Command> {
    let mut command = Command::new(base.get_program());
    for (key, path) in [
        ("IB_RUNTIME", runtime),
        (
            "IB_DEVICE_TYPES",
            Path::new("/Library/Developer/CoreSimulator/Profiles/DeviceTypes"),
        ),
        ("IB_DEVICE_KIT", Path::new("/Library/Developer/DeviceKit")),
    ] {
        trusted_directory(path)?;
        command.arg("-D").arg(format!(
            "{key}={}",
            path.to_str().context("non-UTF-8 runtime path")?
        ));
    }
    command.env_clear();
    for (key, value) in base.get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        }
    }
    command.current_dir(
        base.get_current_dir()
            .context("missing compiler directory")?,
    );
    let mut profile = false;
    let mut replaced = false;
    for arg in base.get_args() {
        if profile {
            let source = arg.to_str().context("invalid compiler profile")?;
            command.arg(compiler_profile(source, services)?);
            profile = false;
            replaced = true;
        } else {
            command.arg(arg);
            profile = arg == "-p";
        }
    }
    if !replaced {
        bail!("expected inline Seatbelt profile; no fallback");
    }
    process::harden(&mut command);
    Ok(command)
}

struct Capture {
    success: bool,
    diagnostics: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}
struct Signals(Vec<signal_hook::SigId>);
impl Drop for Signals {
    fn drop(&mut self) {
        for id in self.0.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}
struct ChildGroup(std::process::Child);
impl Drop for ChildGroup {
    fn drop(&mut self) {
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
        let _ = self.0.wait();
    }
}
fn capture(mut command: Command, limit: Duration) -> Result<Capture> {
    capture_cancellable(&mut command, limit, None)
}
fn capture_cancellable(
    command: &mut Command,
    limit: Duration,
    external: Option<&AtomicBool>,
) -> Result<Capture> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut signals = Signals(vec![]);
    for signal in [libc::SIGINT, libc::SIGTERM] {
        signals
            .0
            .push(signal_hook::flag::register(signal, cancelled.clone())?);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = ChildGroup(command.spawn()?);
    let stdout = child.0.stdout.take().context("missing compiler stdout")?;
    let stderr = child.0.stderr.take().context("missing compiler stderr")?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            bail!(std::io::Error::last_os_error());
        }
    }
    let mut streams: [Box<dyn Read>; 2] = [Box::new(stdout), Box::new(stderr)];
    let mut eof = [false; 2];
    let mut diagnostics = vec![];
    let mut split = [Vec::new(), Vec::new()];
    let mut truncated = false;
    let deadline = Instant::now() + limit;
    let mut exited = None;
    let mut status = None;
    loop {
        for (i, stream) in streams.iter_mut().enumerate() {
            // Bound each drain too: a noisy compiler cannot starve deadlines.
            for _ in 0..16 {
                let mut bytes = [0; 4096];
                match stream.read(&mut bytes) {
                    Ok(0) => {
                        eof[i] = true;
                        break;
                    }
                    Ok(n) => {
                        let keep = n.min(LOG_LIMIT - diagnostics.len());
                        diagnostics.extend_from_slice(&bytes[..keep]);
                        split[i].extend_from_slice(&bytes[..keep]);
                        truncated |= keep < n;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        if status.is_none() {
            status = child.0.try_wait()?;
            if status.is_some() {
                exited = Some(Instant::now());
            }
        }
        if cancelled.load(Ordering::Relaxed)
            || external.is_some_and(|flag| flag.load(Ordering::Relaxed))
        {
            bail!("XIB compilation cancelled; no artifact published");
        }
        if let Some(done) = exited {
            if eof.iter().all(|x| *x) || done.elapsed() >= Duration::from_millis(250) {
                break;
            }
        }
        if Instant::now() >= deadline {
            bail!("XIB compiler deadline exceeded; no artifact published");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if truncated {
        diagnostics.extend_from_slice(b"\n[compiler diagnostics truncated]\n");
    }
    Ok(Capture {
        success: status.is_some_and(|s| s.success()),
        diagnostics,
        stdout: std::mem::take(&mut split[0]),
        stderr: std::mem::take(&mut split[1]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simulator_service_opt_in_preserves_the_compiler_boundary() {
        let base = "(version 1)\n(deny default)\n(deny network*)\n(deny file-read* (literal \"/host/canary\"))\n(deny process-info*)\n";
        for services in [SimulatorServices::Restricted, SimulatorServices::Enabled] {
            let profile = compiler_profile(base, services).unwrap();
            assert!(profile.starts_with(base.strip_suffix("(deny process-info*)\n").unwrap()));
            assert!(profile.ends_with("\n(deny process-info*)\n"));
            assert_eq!(profile.matches("(deny process-info*)").count(), 1);
            assert!(!profile.contains("(allow network"));
            assert!(!profile.contains("(allow default"));
            assert!(
                profile.contains("(global-name \"com.apple.CoreSimulator.SimLaunchHost-arm64\")")
            );
            assert_eq!(
                profile.contains(
                    "(xpc-service-name \"com.apple.CoreSimulator.CoreSimulatorService\")"
                ),
                services == SimulatorServices::Enabled
            );
            assert_eq!(
                profile.contains("(deny mach-lookup"),
                services == SimulatorServices::Restricted
            );
        }
        assert_eq!(SimulatorServices::default(), SimulatorServices::Restricted);
        assert!(
            compiler_profile("(version 1)(allow default)", SimulatorServices::Enabled).is_err()
        );
    }

    #[cfg(target_os = "macos")]
    const GUARD_SOURCE: &str = include_str!("../tests/support/xib_guard.c");

    #[cfg(target_os = "macos")]
    fn compile_guard(
        compiler: &Path,
        env: &BTreeMap<String, String>,
        source: &Path,
        output: &Path,
    ) -> Result<()> {
        let developer = Path::new(
            env.get("DEVELOPER_DIR")
                .context("missing test developer directory")?,
        )
        .canonicalize()?;
        let bundled = developer.join("Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk");
        let sdk = if bundled.is_dir() {
            bundled
        } else {
            developer.join("SDKs/MacOSX.sdk")
        }
        .canonicalize()
        .context("selected developer installation has no MacOSX SDK for the fixed canary helper")?;
        if !sdk.starts_with(&developer) || !sdk.is_dir() {
            bail!("canary SDK must remain inside the selected developer installation");
        }
        let mut command = Command::new(compiler);
        command
            .env_clear()
            .envs(env)
            .arg("-isysroot")
            .arg(sdk)
            .arg(source)
            .arg("-o")
            .arg(output);
        process::harden(&mut command);
        let result = capture(command, Duration::from_secs(30))?;
        if !result.success {
            bail!(
                "fixed canary helper compilation failed: {}",
                String::from_utf8_lossy(&result.diagnostics).escape_debug()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn fixed_canary_helper_builds_with_a_cleared_environment_and_explicit_sdk() {
        // Uses the actual native-test C source and compilation helper. No
        // Seatbelt launch, service connection, file probe or networking occurs.
        let temp = tempfile::tempdir().unwrap();
        let private = temp.path().canonicalize().unwrap();
        let xcode = Path::new("/Applications/Xcode.app/Contents/Developer");
        let developer = if xcode.is_dir() {
            xcode
        } else {
            Path::new("/Library/Developer/CommandLineTools")
        };
        let compiler = if xcode.is_dir() {
            developer.join("Toolchains/XcodeDefault.xctoolchain/usr/bin/clang")
        } else {
            developer.join("usr/bin/clang")
        };
        let env = BTreeMap::from([
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("DEVELOPER_DIR".into(), developer.to_str().unwrap().into()),
            ("HOME".into(), private.to_str().unwrap().into()),
            ("CFFIXED_USER_HOME".into(), private.to_str().unwrap().into()),
            ("TMPDIR".into(), private.to_str().unwrap().into()),
        ]);
        let source = private.join("guard.c");
        let executable = private.join("guard");
        std::fs::write(&source, GUARD_SOURCE).unwrap();
        compile_guard(&compiler, &env, &source, &executable).unwrap();
        // Usage-error branch exits before opening files or creating a socket.
        assert_eq!(
            Command::new(executable)
                .env_clear()
                .status()
                .unwrap()
                .code(),
            Some(64)
        );
    }

    #[test]
    fn compiler_deadline_kills_the_process_group_without_waiting_for_open_pipes() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & wait"]);
        process::harden(&mut command);
        let started = Instant::now();
        let error = capture(command, Duration::from_millis(100))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("deadline"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn diagnostics_are_drained_with_a_fixed_memory_bound() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "i=0; while [ $i -lt 6000 ]; do printf 'compiler-output-line\\n'; i=$((i+1)); done",
        ]);
        process::harden(&mut command);
        let output = capture(command, Duration::from_secs(5)).unwrap();
        assert!(output.success);
        assert!(output.diagnostics.len() < LOG_LIMIT + 100);
        assert!(output
            .diagnostics
            .ends_with(b"[compiler diagnostics truncated]\n"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "REAL exact compiler-profile canary/network test; explicit Xcode/runtime approval; Terminal required"]
    fn compiler_profile_denies_host_canaries_and_ip_networking() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let secret = project.path().join(".env");
        std::fs::write(&secret, b"SYNTHETIC_XIB_HOST_CANARY").unwrap();
        std::fs::write(outside.path(), b"SYNTHETIC_XIB_OUTSIDE_CANARY").unwrap();
        let runtime = approve_runtime(Path::new(
            &std::env::var_os("AGENTVAULT_TEST_SIMULATOR_RUNTIME")
                .expect("explicit runtime approval required"),
        ))
        .unwrap();
        let mut config = Config::for_host();
        config.toolchains.ios = Some(crate::policy::toolchains::Ios {
            xcode_app: std::env::var_os("AGENTVAULT_TEST_XCODE_APP")
                .expect("explicit Xcode approval required")
                .into(),
        });
        let backend = Backend::select(project.path(), &config).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("workspace");
        std::fs::create_dir(&work).unwrap();
        let work = work.canonicalize().unwrap();
        let env = backend.environment(&config, &[], &work).unwrap();
        backend.probe(project.path(), &work, &env).unwrap();
        let source = temp.path().join("guard.c");
        std::fs::write(&source, GUARD_SOURCE).unwrap();
        compile_guard(
            &backend.resolve("clang").unwrap(),
            &env,
            &source,
            &work.join("guard"),
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let mut host = Command::new(work.join("guard"));
        host.env_clear().args([
            "allowed",
            secret.to_str().unwrap(),
            outside.path().to_str().unwrap(),
            &port,
        ]);
        process::harden(&mut host);
        let host_result = capture(host, Duration::from_secs(5)).unwrap();
        assert!(
            host_result.success,
            "host positive control failed: {}",
            String::from_utf8_lossy(&host_result.diagnostics).escape_debug()
        );
        let base = backend
            .offline_compiler_command(
                project.path(),
                &work,
                &env,
                &backend.resolve("/bin/sh").unwrap(),
                &[
                    "-c".into(),
                    "exec ./guard denied \"$@\"".into(),
                    "canary".into(),
                    secret.to_str().unwrap().into(),
                    outside.path().to_str().unwrap().into(),
                    port,
                ],
            )
            .unwrap();
        let mut modes = vec![SimulatorServices::Restricted];
        if std::env::var("AGENTVAULT_TEST_COMPILER_SIMULATOR_SERVICES").as_deref() == Ok("1") {
            modes.push(SimulatorServices::Enabled);
        }
        for mode in modes {
            let sandbox_result = capture(
                compiler_access_with_services(&base, &runtime, mode).unwrap(),
                Duration::from_secs(5),
            )
            .unwrap();
            assert!(sandbox_result.success,
            "exact compiler profile did not explicitly deny both host canaries and an active TCP listener: {}",
            String::from_utf8_lossy(&sandbox_result.diagnostics).escape_debug());
            println!("Verified direct host-file/TCP denials for {mode:?} compiler profile.");
        }
    }
}
