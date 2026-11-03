//! Experimental native macOS filesystem confinement. Never uses an allow-default profile.
use super::process;
use anyhow::{bail, Context, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    process::Command,
};

const SYSTEM_READ_ROOTS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/share",
    "/System/Library",
    "/Library/Apple/System/Library",
    "/System/Volumes/Preboot/Cryptexes/OS/usr/lib",
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library",
];
const SYSTEM_FILES: &[&str] = &[
    "/private/etc/hosts",
    "/private/etc/resolv.conf",
    "/private/var/run/resolv.conf",
    "/private/etc/services",
    "/private/etc/protocols",
    "/private/etc/localtime",
    "/private/etc/ssl/cert.pem",
    "/private/etc/ssl/openssl.cnf",
    "/Library/Preferences/.GlobalPreferences.plist",
];
// /bin/sh can consult this administrator-controlled selector during startup.
// Preserve the alias traversal path as well as its approved runtime target.
const SYSTEM_ALIASES: &[&str] = &["/private/var/select/sh"];
const CODEX_SYSTEM_FILES: &[&str] = &["requirements.toml", "managed_config.toml", "config.toml"];
pub const XCODE_LICENSE_RECORD: &str = "/Library/Preferences/com.apple.dt.Xcode.plist";
pub const XCODE_CORE_SIMULATOR: &str =
    "/Library/Developer/PrivateFrameworks/CoreSimulator.framework";

// Fixed, inspected system dependencies; never auto-grant arbitrary dylib paths.
const XCODE_FRAMEWORKS: &[(&str, &str)] = &[
    ("XCODE_CORE_SIMULATOR", XCODE_CORE_SIMULATOR),
    (
        "XCODE_ROCKIT",
        "/Library/Developer/PrivateFrameworks/ROCKit.framework",
    ),
    (
        "XCODE_DVT_DOWNLOADS",
        "/Library/Developer/PrivateFrameworks/DVTDownloads.framework",
    ),
];

fn validate_xcode_framework(path: &Path) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || path.canonicalize()? != path {
        bail!("Xcode system framework must be a real directory without aliased ancestors");
    }
    trusted(path, false).context("Xcode system framework must be root-controlled")?;
    let name = path.file_stem().context("framework requires a name")?;
    let executable = path.join(name).canonicalize()?;
    if !executable.starts_with(path) || !executable.is_file() {
        bail!("Xcode framework executable must remain inside its approved framework");
    }
    trusted(&executable, false)?;
    Ok(path.to_owned())
}
/// The system acceptance record is read-only. Never use a user preferences
/// domain, generate acceptance values, or run license acceptance commands.
fn validate_license_record(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_file() || meta.nlink() != 1 || meta.len() > 65536 {
                bail!("Xcode system license record must be a small regular single-link file");
            }
            trusted(path, false).context("Xcode license record must be root-controlled")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            trusted(
                path.parent().context("license record missing parent")?,
                false,
            )?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub const PUBLIC_CA_BUNDLE: &str = "/private/etc/ssl/cert.pem";

/// Public CA certificates, never the host user's Keychain or a client key.
pub fn public_ca_bundle() -> Result<&'static str> {
    let path = Path::new(PUBLIC_CA_BUNDLE);
    let metadata = std::fs::symlink_metadata(path).context(
        "required public macOS CA bundle is unavailable; TLS verification is not disabled",
    )?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() == 0 {
        bail!("public CA bundle must be a nonempty regular single-link file");
    }
    trusted(path, false)
        .context("public CA bundle and ancestors must be administrator-controlled")?;
    Ok(PUBLIC_CA_BUNDLE)
}
fn text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow::anyhow!("sandbox paths must be UTF-8"))
}
fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
pub(crate) fn trusted(path: &Path, allow_user: bool) -> Result<()> {
    // Standard Homebrew trees are commonly writable by macOS administrators.
    // Explicit runtime approval trusts those administrators as well as its owner;
    // world-writable and non-admin group-writable installations remain rejected.
    #[cfg(target_os = "macos")]
    let admin_gid = if allow_user {
        let group = unsafe { libc::getgrnam(c"admin".as_ptr()) };
        if group.is_null() {
            None
        } else {
            Some(unsafe { (*group).gr_gid })
        }
    } else {
        None
    };
    #[cfg(not(target_os = "macos"))]
    let admin_gid: Option<u32> = None;
    for ancestor in path.ancestors() {
        let m = std::fs::metadata(ancestor)?;
        if (m.uid() != 0 && (!allow_user || m.uid() != unsafe { libc::geteuid() }))
            || m.mode() & 0o002 != 0
            || (m.mode() & 0o020 != 0 && admin_gid != Some(m.gid()))
            || m.mode() & 0o6000 != 0
        {
            bail!("runtime and ancestors must be owned by root or the explicitly approving user, not world-writable or writable by a non-admin group, and not setuid/setgid");
        }
    }
    Ok(())
}
pub fn validate_runtime_roots(project: &Path, roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let project = project.canonicalize()?;
    let mut result = Vec::new();
    for root in roots {
        if !root.is_absolute() || root.components().any(|p| matches!(p, Component::ParentDir)) {
            bail!("runtime roots must be absolute, without traversal");
        }
        let root = root
            .canonicalize()
            .context("approved runtime root does not exist")?;
        // No home, /private, /System, or whole /usr approval. This MVP supports
        // explicit Homebrew/system-local tool installations, not host login trees.
        if ![Path::new("/opt"), Path::new("/usr/local")]
            .iter()
            .any(|base| root.starts_with(base) && root != *base)
            && root != Path::new("/usr/local")
        {
            bail!("macOS runtime roots must be narrow trees under /opt, or /usr/local; host homes and temporary trees cannot be approved");
        }
        if overlaps(&root, &project) {
            bail!("project overlaps an approved runtime tree");
        }
        if !root.is_dir() {
            bail!("runtime root is not a directory");
        }
        trusted(&root, true)?;
        text(&root)?;
        if !result.contains(&root) {
            result.push(root);
        }
    }
    for root in SYSTEM_READ_ROOTS {
        if project.starts_with(root) || Path::new(root).starts_with(&project) {
            bail!("project overlaps macOS system runtime paths");
        }
    }
    Ok(result)
}
pub fn resolve(name: &str, roots: &[PathBuf]) -> Result<PathBuf> {
    let requested = Path::new(name);
    if !requested.is_absolute() && requested.components().count() != 1 {
        bail!("executable must be a basename or absolute path");
    }
    let mut candidates = Vec::new();
    if requested.is_absolute() {
        candidates.push(requested.to_owned());
    } else {
        for root in roots {
            candidates.push(root.join("bin").join(name));
        }
        for root in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
            candidates.push(Path::new(root).join(name));
        }
    }
    for candidate in candidates {
        let Ok(path) = candidate.canonicalize() else {
            continue;
        };
        let approved = roots.iter().any(|r| path.starts_with(r));
        if !approved && !SYSTEM_READ_ROOTS.iter().any(|r| path.starts_with(r)) {
            continue;
        }
        let m = std::fs::metadata(&path)?;
        if !m.is_file() || m.mode() & 0o111 == 0 {
            continue;
        }
        trusted(&path, approved)?;
        return Ok(path);
    }
    bail!("executable unavailable in approved macOS runtimes; explicitly configure sandbox.runtime_roots (e.g. /opt/homebrew) for Homebrew tools; home-installed agents are not imported")
}

pub(crate) struct Access<'a> {
    pub runtimes: &'a [PathBuf],
    pub sdks: &'a [PathBuf],
    pub xcode_license: bool,
    pub network: Network,
}
#[derive(Clone, Copy)]
pub(crate) enum Network {
    Agent,
    OfflineCompiler,
}
pub struct Profile {
    pub source: String,
    pub parameters: Vec<(String, String)>,
}
pub fn profile(
    project: &Path,
    work: &Path,
    home: &Path,
    tmp: &Path,
    runtime_roots: &[PathBuf],
) -> Result<Profile> {
    profile_with_access(
        project,
        work,
        home,
        tmp,
        Access {
            runtimes: runtime_roots,
            sdks: &[],
            xcode_license: false,
            network: Network::Agent,
        },
    )
}
fn profile_with_access(
    project: &Path,
    work: &Path,
    home: &Path,
    tmp: &Path,
    access: Access<'_>,
) -> Result<Profile> {
    let project = project.canonicalize()?;
    let work = work.canonicalize()?;
    let home = home.canonicalize()?;
    let tmp = tmp.canonicalize()?;
    let mut roots = validate_runtime_roots(&project, access.runtimes)?;
    for root in access.sdks {
        roots.push(crate::policy::toolchains::approve(&project, root)?);
    }
    let parent = work.parent().context("workspace needs private parent")?;
    if overlaps(&project, &work)
        || home.parent() != Some(parent)
        || tmp.parent() != Some(parent)
        || home == tmp
        || home == work
        || tmp == work
    {
        bail!("workspace, private home and temporary directory must be separate siblings outside the project");
    }
    let parent_meta = std::fs::metadata(parent)?;
    if parent_meta.mode() & 0o077 != 0 || parent_meta.uid() != unsafe { libc::geteuid() } {
        bail!("workspace parent must be private and owned by the current user");
    }
    let mut p = Profile {
        source: include_str!("seatbelt.sb").into(),
        parameters: vec![],
    };
    match access.network {
        Network::Agent => p.source.push_str(
            "\n; Agent outbound IP and the exact system DNS resolver socket.\n(allow network-outbound (remote ip)\n    (literal \"/private/var/run/mDNSResponder\"))\n",
        ),
        Network::OfflineCompiler => p.source.push_str(
            "\n; Omit agent networking grants entirely. A family deny does not\n; revoke the agent's operation-specific IP allowance on the tested host.\n(deny network*)\n(deny network-outbound network-inbound network-bind)\n",
        ),
    }
    let mut ancestors = BTreeSet::new();
    for (name, path) in [
        ("WORKSPACE", work),
        ("PRIVATE_HOME", home),
        ("PRIVATE_TMP", tmp),
    ] {
        for ancestor in path.ancestors().skip(1) {
            ancestors.insert(ancestor.to_owned());
        }
        p.parameters.push((name.into(), text(&path)?.into()));
    }
    // Parameter values never become SBPL source, even for quote/newline filenames.
    for (index, root) in roots.iter().enumerate() {
        let name = format!("RUNTIME_{index}");
        p.source.push_str(&format!(
            "\n(allow file-read* file-map-executable (subpath (param \"{name}\")))\n"
        ));
        p.parameters.push((name, text(root)?.into()));
        for ancestor in root.ancestors().skip(1) {
            ancestors.insert(ancestor.to_owned());
        }
    }
    for (index, root) in SYSTEM_READ_ROOTS.iter().enumerate() {
        let name = format!("SYSTEM_{index}");
        p.source.push_str(&format!(
            "\n(allow file-read* file-map-executable (subpath (param \"{name}\")))\n"
        ));
        p.parameters.push((name, root.to_string()));
        for ancestor in Path::new(root).ancestors().skip(1) {
            ancestors.insert(ancestor.to_owned());
        }
    }
    for (index, file) in SYSTEM_FILES.iter().enumerate() {
        if !Path::new(file).exists() {
            continue;
        }
        let actual = Path::new(file).canonicalize()?;
        if actual.starts_with(&project) {
            bail!("project overlaps an exposed runtime configuration file");
        }
        // macOS resolvers may readlink/open the alias before using the final
        // vnode. A grant for only the canonical target misses that operation.
        let mut paths = vec![actual, PathBuf::from(file)];
        if let Ok(alias) = Path::new(file).strip_prefix("/private") {
            paths.push(Path::new("/").join(alias));
        }
        paths.sort();
        paths.dedup();
        for (alias_index, path) in paths.iter().enumerate() {
            let name = format!("CONFIG_{index}_{alias_index}");
            p.source.push_str(&format!(
                "\n(allow file-read* (literal (param \"{name}\")))\n"
            ));
            p.parameters.push((name, text(path)?.into()));
            for ancestor in path.ancestors().skip(1) {
                ancestors.insert(ancestor.to_owned());
            }
        }
    }
    if access.xcode_license {
        // Xcode's UTI-based workspace recognition needs the LaunchServices
        // mapping endpoint. Do not allow lsd.modifydb or Simulator services.
        p.source
            .push_str("\n(allow mach-lookup (global-name \"com.apple.lsd.mapdb\"))\n");
        let path = Path::new(XCODE_LICENSE_RECORD);
        validate_license_record(path)?;
        if overlaps(path, &project) {
            bail!("project overlaps Xcode license record");
        }
        p.source
            .push_str("\n(allow file-read* (literal (param \"XCODE_LICENSE_RECORD\")))\n");
        p.parameters
            .push(("XCODE_LICENSE_RECORD".into(), text(path)?.into()));
        for ancestor in path.ancestors().skip(1) {
            ancestors.insert(ancestor.to_owned());
        }
        for (parameter, path) in XCODE_FRAMEWORKS {
            let framework = Path::new(path);
            match std::fs::symlink_metadata(framework) {
                Ok(_) => {
                    let framework = validate_xcode_framework(framework)?;
                    if overlaps(&framework, &project) {
                        bail!("project overlaps Xcode system framework");
                    }
                    p.source.push_str(&format!(
                        "\n(allow file-read* file-map-executable (subpath (param \"{parameter}\")))\n"
                    ));
                    p.parameters
                        .push((parameter.to_string(), text(&framework)?.into()));
                    for ancestor in framework.ancestors().skip(1) {
                        ancestors.insert(ancestor.to_owned());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    // Codex must distinguish absent optional system policy from inaccessible
    // policy. Keep literal probes even when files do not exist. Do not expose
    // a whole directory or silently import existing defaults with credentials.
    let codex_system_dir = Path::new("/private/etc/codex");
    match std::fs::symlink_metadata(codex_system_dir) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                bail!("system Codex directory must be a real directory, not a symlink");
            }
            trusted(codex_system_dir, false)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            trusted(Path::new("/private/etc"), false)?;
        }
        Err(error) => return Err(error.into()),
    }
    for (index, filename) in CODEX_SYSTEM_FILES.iter().enumerate() {
        let actual = codex_system_dir.join(filename);
        match std::fs::symlink_metadata(&actual) {
            Ok(metadata) => {
                if *filename != "requirements.toml" {
                    bail!("existing system Codex defaults are not imported automatically; explicit support is required for {:?} because defaults can contain credentials", actual);
                }
                if !metadata.is_file() || metadata.nlink() != 1 {
                    bail!("system Codex requirements must be a regular, single-link file");
                }
                trusted(&actual, false)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if actual.starts_with(&project) {
            bail!("project overlaps system Codex policy");
        }
        for (suffix, path) in [
            ("CANONICAL", actual),
            ("ALIAS", Path::new("/etc/codex").join(filename)),
        ] {
            let name = format!("CODEX_SYSTEM_{index}_{suffix}");
            p.source.push_str(&format!(
                "\n(allow file-read* (literal (param \"{name}\")))\n"
            ));
            p.parameters.push((name, text(&path)?.into()));
            for ancestor in path.ancestors().skip(1) {
                ancestors.insert(ancestor.to_owned());
            }
        }
    }
    for (index, alias) in SYSTEM_ALIASES.iter().enumerate() {
        let alias = Path::new(alias);
        if !alias.try_exists()? {
            continue;
        }
        let actual = alias.canonicalize()?;
        if !actual.is_file()
            || !SYSTEM_READ_ROOTS
                .iter()
                .any(|root| actual.starts_with(root))
            || actual.starts_with(&project)
        {
            bail!("system shell selector must resolve to an approved system runtime");
        }
        trusted(alias.parent().context("system alias has no parent")?, false)?;
        trusted(&actual, false)?;
        let name = format!("SYSTEM_ALIAS_{index}");
        p.source.push_str(&format!(
            "\n(allow file-read* (literal (param \"{name}\")))\n"
        ));
        p.parameters.push((name, text(alias)?.into()));
        for ancestor in alias.ancestors().skip(1) {
            ancestors.insert(ancestor.to_owned());
        }
    }
    #[cfg(target_os = "macos")]
    if unsafe { libc::isatty(0) } == 1 {
        let mut buffer = [0i8; 1024];
        if unsafe { libc::ttyname_r(0, buffer.as_mut_ptr(), buffer.len()) } != 0 {
            bail!("could not identify the interactive terminal");
        }
        let path = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }.to_str()?;
        if !Path::new(path).starts_with("/dev") {
            bail!("unexpected terminal device path");
        }
        p.source.push_str(
            "\n(allow file-read* file-write-data file-ioctl (literal (param \"TTY_DEVICE\")))\n",
        );
        p.parameters.push(("TTY_DEVICE".into(), path.into()));
        ancestors.insert(PathBuf::from("/dev"));
    }
    for (index, ancestor) in ancestors.into_iter().enumerate() {
        let name = format!("ANCESTOR_{index}");
        p.source.push_str(&format!(
            "\n(allow file-read-metadata (literal (param \"{name}\")))\n"
        ));
        p.parameters.push((name, text(&ancestor)?.into()));
    }
    // Preserve the exact rule composition demonstrated by the real diagnostic:
    // the startup self rule remains, followed by the explicit family denial
    // after all grants. Removing the self rule broke macOS runtime bootstrap.
    // Do not move this into the initial template or append grants after it.
    p.source.push_str("\n(deny process-info*)\n");
    Ok(p)
}
/// Seatbelt has no reliable loopback/port-scoped inbound primitive. An explicit
/// opt-in permits TCP listeners; otherwise preview denies TCP bind/inbound.
/// Normal agent profiles do not call this function and remain unchanged.
pub fn configure_preview_network(source: &mut String, allow_listen: bool) -> Result<()> {
    let suffix = "\n(deny process-info*)\n";
    if !source.ends_with(suffix) {
        bail!("missing final process isolation rule");
    }
    source.truncate(source.len() - suffix.len());
    let decision = if allow_listen { "allow" } else { "deny" };
    source.push_str(&format!(
        "\n({decision} network-bind network-inbound (local tcp))\n"
    ));
    source.push_str(suffix);
    Ok(())
}

pub fn command(
    project: &Path,
    work: &Path,
    env: &BTreeMap<String, String>,
    exe: &Path,
    args: &[String],
    roots: &[PathBuf],
) -> Result<Command> {
    command_with_access(
        project,
        work,
        env,
        exe,
        args,
        Access {
            runtimes: roots,
            sdks: &[],
            xcode_license: false,
            network: Network::Agent,
        },
        None,
    )
}

pub fn preview_command(
    project: &Path,
    work: &Path,
    env: &BTreeMap<String, String>,
    exe: &Path,
    args: &[String],
    roots: &[PathBuf],
    allow_listen: bool,
) -> Result<Command> {
    command_with_access(
        project,
        work,
        env,
        exe,
        args,
        Access {
            runtimes: roots,
            sdks: &[],
            xcode_license: false,
            network: Network::Agent,
        },
        Some(allow_listen),
    )
}

pub(crate) fn command_with_access(
    project: &Path,
    work: &Path,
    env: &BTreeMap<String, String>,
    exe: &Path,
    args: &[String],
    access: Access<'_>,
    preview_listen: Option<bool>,
) -> Result<Command> {
    if !cfg!(target_os = "macos") || unsafe { libc::geteuid() } == 0 {
        bail!("Seatbelt requires an unprivileged macOS user");
    }
    let helper = resolve("sandbox-exec", &[])?;
    let mut roots = access.runtimes.to_vec();
    roots.extend_from_slice(access.sdks);
    let exe = resolve(text(exe)?, &roots)?;
    let home = Path::new(env.get("HOME").context("missing private HOME")?);
    let tmp = Path::new(env.get("TMPDIR").context("missing private TMPDIR")?);
    let mut p = profile_with_access(project, work, home, tmp, access)?;
    if let Some(allow_listen) = preview_listen {
        configure_preview_network(&mut p.source, allow_listen)?;
    }
    let mut command = Command::new(helper);
    command.env_clear().envs(env).current_dir(work);
    for (name, value) in p.parameters {
        command.arg("-D").arg(format!("{name}={value}"));
    }
    command.arg("-p").arg(p.source).arg(exe).args(args);
    process::harden(&mut command);
    Ok(command)
}
pub fn probe(
    project: &Path,
    work: &Path,
    env: &BTreeMap<String, String>,
    roots: &[PathBuf],
) -> Result<()> {
    probe_with_access(
        project,
        work,
        env,
        Access {
            runtimes: roots,
            sdks: &[],
            xcode_license: false,
            network: Network::Agent,
        },
    )
}
pub(crate) fn probe_with_access(
    project: &Path,
    work: &Path,
    env: &BTreeMap<String, String>,
    access: Access<'_>,
) -> Result<()> {
    let mut filtered = env.clone();
    filtered.remove("OPENAI_API_KEY");
    filtered.remove("ANTHROPIC_API_KEY");
    let canary = tempfile::Builder::new()
        .prefix("agentvault-host-canary-")
        .tempfile()?;
    std::fs::write(canary.path(), b"SYNTHETIC_PREFLIGHT_CANARY")?;
    let script = r#"
set -eu
fail() { printf 'AgentVault macOS isolation check failed: %s\n' "$1" >&2; exit 1; }
# The canary is present and readable on the host; the sandbox must deny it.
if /bin/cat "$2" >/dev/null 2>&1; then fail host-canary-readable; fi
if /bin/ls "$1" >/dev/null 2>&1; then fail original-project-listable; fi
if /bin/cat "$1/.env" >/dev/null 2>&1; then fail original-env-readable; fi
[ ! -e .env ] || fail excluded-env-present
[ ! -e .env.production ] || fail excluded-production-env-present
[ -z "${SSH_AUTH_SOCK+x}" ] || fail ssh-agent-environment
[ -z "${DYLD_INSERT_LIBRARIES+x}" ] || fail loader-environment
[ "${CFFIXED_USER_HOME-}" = "$HOME" ] || fail cocoa-home-not-private
printf probe > .agentvault-probe || fail workspace-not-writable
/bin/rm .agentvault-probe || fail workspace-cleanup
printf probe > "$HOME/probe" || fail private-home-not-writable
/bin/rm "$HOME/probe" || fail private-home-cleanup
printf probe > "$TMPDIR/probe" || fail private-tmp-not-writable
/bin/rm "$TMPDIR/probe" || fail private-tmp-cleanup
printf AGENTVAULT_MACOS_PROBE_OK
"#;
    let args = vec![
        "-c".into(),
        script.into(),
        "agentvault-probe".into(),
        text(project)?.into(),
        text(canary.path())?.into(),
    ];
    let result = command_with_access(
        project,
        work,
        &filtered,
        &resolve("sh", &[])?,
        &args,
        access,
        None,
    )?
    .output()
    .context("macOS sandbox startup or descriptor hardening failed")?;
    if !result.status.success() || result.stdout != b"AGENTVAULT_MACOS_PROBE_OK" {
        let detail = super::bubblewrap::backend_diagnostic(&result.stderr, env);
        bail!("macOS sandbox startup/isolation probe failed ({}): {}. Nested/managed sessions may prohibit sandbox_apply; run from your own Terminal. No unsandboxed fallback",result.status,detail);
    }
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::{
        policy::config::Config, sandbox::backend::Backend, security::paths::Dir, workspace::prepare,
    };
    #[test]
    fn offline_compiler_profiles_omit_agent_network_grants() {
        let project = tempfile::tempdir().unwrap();
        let config = Config::for_host();
        let backend = Backend::select(project.path(), &config).unwrap();
        let matcher = crate::policy::matcher::Matcher::new(&config).unwrap();
        let work = prepare::prepare(&Dir::open(project.path()).unwrap(), &matcher).unwrap();
        let env = backend.environment(&config, &[], work.path()).unwrap();
        let shell = backend.resolve("/bin/sh").unwrap();
        let agent = backend
            .command(project.path(), work.path(), &env, &shell, &[])
            .unwrap();
        let preview = backend
            .preview_command(project.path(), work.path(), &env, &shell, &[], false)
            .unwrap();
        let offline = backend
            .offline_compiler_command(project.path(), work.path(), &env, &shell, &[])
            .unwrap();
        let inline = |command: &Command| {
            let args: Vec<_> = command.get_args().collect();
            let index = args.iter().position(|arg| *arg == "-p").unwrap();
            args[index + 1].to_str().unwrap().to_owned()
        };
        for command in [&agent, &preview] {
            let source = inline(command);
            assert!(source.contains("(allow network-outbound (remote ip)"));
            assert!(source.contains("(literal \"/private/var/run/mDNSResponder\")"));
        }
        let source = inline(&offline);
        assert!(!source.contains("(allow network-"));
        assert!(!source.contains("(remote ip)"));
        assert!(source.contains("(deny network-outbound network-inbound network-bind)"));
        assert!(source.ends_with("\n(deny process-info*)\n"));
    }
    #[test]
    fn profiles_parameterize_paths_and_do_not_expose_data_volume() {
        let parent = tempfile::tempdir().unwrap();
        let project = parent.path().join("project\") (allow default)");
        std::fs::create_dir(&project).unwrap();
        let config = Config::for_host();
        let backend = Backend::select(&project, &config).unwrap();
        let matcher = crate::policy::matcher::Matcher::new(&config).unwrap();
        let work = prepare::prepare(&Dir::open(&project).unwrap(), &matcher).unwrap();
        let env = backend.environment(&config, &[], work.path()).unwrap();
        let unusual_work = work.temp.path().join("copy\") (allow default)");
        std::fs::create_dir(&unusual_work).unwrap();
        let p = profile(
            &project,
            &unusual_work,
            Path::new(&env["HOME"]),
            Path::new(&env["TMPDIR"]),
            &[],
        )
        .unwrap();
        assert!(p
            .parameters
            .iter()
            .any(|(key, value)| key == "WORKSPACE" && value.contains("(allow default)")));
        assert!(!p.source.contains("(allow default)"));
        assert!(p.source.contains("(deny default)"));
        assert!(!p
            .parameters
            .iter()
            .filter(|(key, _)| !key.starts_with("ANCESTOR_"))
            .any(|(_, value)| value == "/System"
                || value == "/System/Volumes/Data"
                || value == "/Users"));
        assert!(!p.source.contains("com.apple.SecurityServer"));
        assert!(!p.source.contains("(allow mach-lookup)"));
    }
    #[test]
    fn private_directory_cleanup_does_not_follow_a_replaced_home() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join(".env"), "SYNTHETIC_HOST_SECRET").unwrap();
        let config = Config::for_host();
        let backend = Backend::select(project.path(), &config).unwrap();
        let matcher = crate::policy::matcher::Matcher::new(&config).unwrap();
        let work = prepare::prepare(&Dir::open(project.path()).unwrap(), &matcher).unwrap();
        let env = backend.environment(&config, &[], work.path()).unwrap();
        std::fs::write(
            Path::new(&env["TMPDIR"]).join("cache"),
            "SYNTHETIC_CREDENTIAL_CACHE",
        )
        .unwrap();
        std::fs::remove_dir_all(&env["HOME"]).unwrap();
        std::os::unix::fs::symlink(project.path(), &env["HOME"]).unwrap();
        backend.cleanup_private_dirs(work.path(), &env).unwrap();
        assert_eq!(
            std::fs::read(project.path().join(".env")).unwrap(),
            b"SYNTHETIC_HOST_SECRET"
        );
        assert!(!Path::new(&env["HOME"]).exists());
        assert!(!Path::new(&env["TMPDIR"]).exists());
        assert!(work.path().exists());
    }
    #[test]
    fn xcode_license_record_is_granted_only_for_selected_xcode_and_remains_read_only() {
        let project = tempfile::tempdir().unwrap();
        let config = Config::for_host();
        let backend = Backend::select(project.path(), &config).unwrap();
        let matcher = crate::policy::matcher::Matcher::new(&config).unwrap();
        let work = prepare::prepare(&Dir::open(project.path()).unwrap(), &matcher).unwrap();
        let env = backend.environment(&config, &[], work.path()).unwrap();
        for selected in [false, true] {
            let profile = profile_with_access(
                project.path(),
                work.path(),
                Path::new(&env["HOME"]),
                Path::new(&env["TMPDIR"]),
                Access {
                    runtimes: &[],
                    sdks: &[],
                    xcode_license: selected,
                    network: Network::Agent,
                },
            )
            .unwrap();
            assert_eq!(
                profile
                    .parameters
                    .iter()
                    .any(|(key, value)| key == "XCODE_LICENSE_RECORD"
                        && value == XCODE_LICENSE_RECORD),
                selected
            );
            if selected {
                assert!(profile
                    .source
                    .contains("(allow file-read* (literal (param \"XCODE_LICENSE_RECORD\")))"));
            }
            assert_eq!(
                profile
                    .source
                    .contains("(global-name \"com.apple.lsd.mapdb\")"),
                selected
            );
            assert!(!profile.source.contains("com.apple.lsd.modifydb"));
            assert!(!profile
                .source
                .contains("com.apple.CoreSimulator.CoreSimulatorService"));
            assert!(!profile
                .source
                .contains("allow file-write* (literal (param \"XCODE_LICENSE_RECORD"));
            for (parameter, path) in XCODE_FRAMEWORKS {
                assert_eq!(
                    profile
                        .parameters
                        .iter()
                        .any(|(key, value)| key == parameter && value == path),
                    selected && Path::new(path).exists()
                );
                assert!(!profile
                    .source
                    .contains(&format!("allow file-write* (subpath (param \"{parameter}")));
            }
            assert!(profile.source.ends_with("\n(deny process-info*)\n"));
        }
    }
    #[test]
    fn unsafe_license_record_objects_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        assert!(validate_license_record(temp.path()).is_err());
        let file = temp.path().join("record");
        std::fs::write(&file, b"synthetic").unwrap();
        let link = temp.path().join("alias");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(validate_license_record(&link).is_err());
        std::fs::hard_link(&file, temp.path().join("other")).unwrap();
        assert!(validate_license_record(&file).is_err());
    }
    #[test]
    fn unsafe_xcode_framework_objects_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("framework");
        std::fs::write(&file, b"synthetic").unwrap();
        assert!(validate_xcode_framework(&file).is_err());
        let link = temp.path().join("alias");
        std::os::unix::fs::symlink(temp.path(), &link).unwrap();
        assert!(validate_xcode_framework(&link).is_err());
        assert!(validate_xcode_framework(temp.path()).is_err());
    }
    #[test]
    fn broad_runtime_roots_and_backend_fallback_refused() {
        let project = tempfile::tempdir().unwrap();
        for path in ["/", "/Users", "/private", "/System", "/usr", "/opt"] {
            assert!(validate_runtime_roots(project.path(), &[PathBuf::from(path)]).is_err());
        }
        assert!(Backend::select(project.path(), &Config::defaults()).is_err());
    }
}
