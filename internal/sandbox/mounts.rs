use anyhow::{bail, Context, Result};
use std::{
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};
/// Only trusted administrator-managed installation roots. No host PATH search.
pub fn resolve(name: &str) -> Result<PathBuf> {
    let requested = Path::new(name);
    let candidates: Vec<_> = if requested.is_absolute() {
        vec![requested.to_path_buf()]
    } else {
        if requested.components().count() != 1 {
            bail!("executable must be a basename or absolute path");
        }
        ["/usr/local/bin", "/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(name))
            .collect()
    };
    for p in candidates {
        let Ok(p) = p.canonicalize() else { continue };
        if !["/usr", "/bin", "/lib", "/lib64"]
            .iter()
            .any(|r| p.starts_with(r))
        {
            continue;
        }
        let m = std::fs::metadata(&p)?;
        if !m.is_file() || m.mode() & 0o111 == 0 {
            continue;
        }
        for ancestor in p.ancestors() {
            let m = std::fs::metadata(ancestor)?;
            if m.uid() != 0 || m.mode() & 0o022 != 0 || m.mode() & 0o6000 != 0 {
                bail!("runtime executable and ancestors must be root-owned, non-writable by group/others, and not setuid/setgid");
            }
        }
        return Ok(p);
    }
    bail!("trusted executable unavailable; install under root-owned /usr/local/bin or /usr/bin")
}
pub fn configure(command: &mut Command, root: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    for directory in ["/usr", "/bin", "/lib", "/lib64"] {
        let p = Path::new(directory);
        if p.exists() {
            let canonical = p.canonicalize()?;
            if root.starts_with(&canonical) || canonical.starts_with(&root) {
                bail!("project overlaps exposed runtime directories");
            }
            command.args(["--ro-bind", directory, directory]);
        }
    }
    for p in [
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/ssl/certs",
        "/etc/ca-certificates",
    ] {
        if Path::new(p).exists() {
            let canonical = Path::new(p)
                .canonicalize()
                .context("runtime configuration")?;
            if canonical.starts_with(&root) || root.starts_with(&canonical) {
                bail!("project overlaps exposed runtime configuration");
            }
            command.arg("--ro-bind").arg(canonical).arg(p);
        }
    }
    Ok(())
}
