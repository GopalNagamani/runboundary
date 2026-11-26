use crate::security::paths::Dir;
use anyhow::{bail, Context, Result};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    io::{self, IsTerminal, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const REGISTRY: &str = "https://registry.npmjs.org/";
const PACKAGE: &str = "runboundary@preview";
const UPDATE_COMMAND: &str = "npm install -g runboundary@preview";
const CHECK_INTERVAL: u64 = 24 * 60 * 60;
const CACHE_FILE: &str = "npm-preview.json";
const CACHE_LOCK: &str = "npm-preview.lock";

#[derive(Default, Deserialize, Serialize)]
struct CachedCheck {
    checked_at: u64,
    version: Option<String>,
}

impl CachedCheck {
    fn fresh(&self, now: u64) -> bool {
        now.checked_sub(self.checked_at)
            .is_some_and(|age| age < CHECK_INTERVAL)
    }
}

struct Cache {
    path: PathBuf,
    dir: Dir,
}

impl Cache {
    fn open() -> Result<Self> {
        let home = PathBuf::from(std::env::var_os("HOME").context("host HOME is missing")?);
        if !home.is_absolute() {
            bail!("host HOME must be absolute");
        }
        let home = home.canonicalize()?;
        let relative_dir = Path::new(".cache/runboundary");
        Dir::open(&home)?.ensure_parent(&relative_dir.join(CACHE_FILE))?;
        let path = home.join(relative_dir);
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            bail!("RunBoundary update cache must be private and owned by the current user");
        }
        let dir = Dir::open_absolute(&path)?;
        Ok(Self { path, dir })
    }

    fn read(&self) -> CachedCheck {
        self.dir
            .read_file(CACHE_FILE, 4096)
            .ok()
            .and_then(|(bytes, _)| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    fn store(&self, checked_at: u64, version: Option<&Version>) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new_in(&self.path)?;
        serde_json::to_writer(
            &mut file,
            &CachedCheck {
                checked_at,
                version: version.map(Version::to_string),
            },
        )?;
        file.persist(self.path.join(CACHE_FILE))?;
        Ok(())
    }
}

fn supported() -> bool {
    cfg!(all(target_os = "macos", target_arch = "aarch64"))
}

fn automatic_checks_enabled() -> bool {
    supported() && std::env::var_os("RUNBOUNDARY_NO_UPDATE_CHECK").is_none()
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn installed() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("Cargo package version is SemVer")
}

fn newer(candidate: &Version, current: &Version) -> bool {
    candidate.cmp_precedence(current).is_gt()
}

fn npm() -> Command {
    let mut command = Command::new("npm");
    // The project being sandboxed is untrusted. Keep its .npmrc out of this flow.
    command.current_dir("/").arg("--no-update-notifier");
    command
}

fn lookup() -> Result<Version> {
    let output = npm()
        .args([
            "view",
            PACKAGE,
            "version",
            "--json",
            "--prefer-online",
            "--fetch-retries=0",
            "--fetch-timeout=4000",
        ])
        .arg(format!("--registry={REGISTRY}"))
        .stdin(Stdio::null())
        .output()
        .context("could not run npm to check for updates")?;
    if !output.status.success() {
        bail!(
            "npm could not check the RunBoundary preview ({}); check your registry connection",
            output.status
        );
    }
    let version: String = serde_json::from_slice(&output.stdout)
        .context("npm returned an invalid preview version")?;
    Version::parse(&version).context("npm returned an invalid preview version")
}

fn installed_by_global_npm() -> Result<bool> {
    let output = npm()
        .args(["root", "--global"])
        .stdin(Stdio::null())
        .output()
        .context("could not find npm's global installation directory")?;
    if !output.status.success() {
        bail!("npm could not find its global installation directory");
    }
    let root = Path::new(std::str::from_utf8(&output.stdout)?.trim());
    if !root.is_absolute() {
        bail!("npm returned an invalid global installation directory");
    }
    let expected = root.join("runboundary/bin/runb").canonicalize();
    let current = std::env::current_exe()?.canonicalize()?;
    Ok(expected.is_ok_and(|path| path == current))
}

pub(super) fn execute(check_only: bool) -> Result<()> {
    if !supported() {
        bail!("the npm preview supports Apple Silicon macOS");
    }
    let current = installed();
    let available = lookup()?;
    if let (Ok(cache), Ok(checked_at)) = (Cache::open(), now()) {
        let _ = cache.store(checked_at, Some(&available));
    }
    if !newer(&available, &current) {
        println!("Installed RunBoundary {current}. Newest npm preview: {available}.");
        return Ok(());
    }

    println!("RunBoundary {available} is available (installed: {current}).");
    println!("Update with: {UPDATE_COMMAND}");
    if check_only || !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Ok(());
    }
    if !installed_by_global_npm()? {
        println!("This runb is outside the active npm global installation. Update it using your installation method.");
        return Ok(());
    }

    print!("Install RunBoundary {available} now? [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        return Ok(());
    }
    let status = npm()
        .args(["install", "--global", "--ignore-scripts"])
        .arg(format!("--registry={REGISTRY}"))
        .arg(format!("runboundary@{available}"))
        .status()
        .context("could not run npm to install the update")?;
    if !status.success() {
        bail!("npm update failed ({status})");
    }
    println!("Installed RunBoundary {available}.");
    Ok(())
}

pub(super) fn refresh() -> Result<()> {
    if !automatic_checks_enabled() {
        return Ok(());
    }
    let cache = Cache::open()?;
    // The lock covers the freshness check and lookup across concurrent launches.
    let _lock = cache.dir.lock(Path::new(CACHE_LOCK))?;
    let checked_at = now()?;
    if cache.read().fresh(checked_at) {
        return Ok(());
    }
    let latest = lookup().ok();
    // Cache failures too, so offline terminals do not repeatedly check.
    cache.store(checked_at, latest.as_ref())
}

pub(super) fn notice() {
    if !automatic_checks_enabled() || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return;
    }
    let (Ok(cache), Ok(time)) = (Cache::open(), now()) else {
        return;
    };
    let entry = cache.read();
    if entry.fresh(time) {
        if let Some(version) = entry
            .version
            .and_then(|version| Version::parse(&version).ok())
        {
            if newer(&version, &installed()) {
                eprintln!("RunBoundary {version} is available. Run `runb update` for details.");
            }
        }
        return;
    }
    let Ok(binary) = std::env::current_exe() else {
        return;
    };
    if let Ok(mut child) = Command::new(binary)
        .arg("refresh-updates")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        // Reap the worker if the foreground command is still running.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_uses_semver_precedence() {
        let current = Version::parse("0.1.9").unwrap();
        assert!(newer(&Version::parse("0.1.10").unwrap(), &current));
        assert!(!newer(&Version::parse("0.1.9-rc.1").unwrap(), &current));
        assert!(!newer(&Version::parse("0.1.9+build.2").unwrap(), &current));
    }

    #[test]
    fn cache_expires_and_rejects_a_future_timestamp() {
        let entry = CachedCheck {
            checked_at: 100,
            version: None,
        };
        assert!(entry.fresh(100 + CHECK_INTERVAL - 1));
        assert!(!entry.fresh(100 + CHECK_INTERVAL));
        assert!(!entry.fresh(99));
    }
}
