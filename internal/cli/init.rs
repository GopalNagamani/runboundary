use crate::{
    policy::{config::Config, matcher::Matcher},
    security::paths::Dir,
};
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
pub fn execute(root: &Path, runtime_roots: Vec<PathBuf>) -> Result<()> {
    let dir = Dir::open(root)?;
    if dir
        .metadata(std::ffi::OsStr::new("agentvault.yaml"))
        .is_ok()
    {
        bail!("agentvault.yaml already exists; review or remove it explicitly before initializing");
    }
    let mut config = Config::for_host();
    config.sandbox.runtime_roots = runtime_roots;
    crate::policy::validator::validate(&config)?;
    if config.sandbox.backend == "seatbelt" {
        crate::sandbox::seatbelt::validate_runtime_roots(root, &config.sandbox.runtime_roots)?;
    }
    if !config.sandbox.runtime_roots.is_empty() {
        println!("Explicitly approved read-only runtimes: {:?}; their owner and macOS admin-group writers are trusted",config.sandbox.runtime_roots);
    }
    let matcher = Matcher::new(&config)?;
    let count = count(&dir, Path::new(""), &matcher)?;
    dir.create(
        Path::new("agentvault.yaml"),
        serde_yaml::to_string(&config)?.as_bytes(),
        0o600,
    )?;
    println!("Created agentvault.yaml. Detected {count} protected paths/subtrees without reading their contents.");
    Ok(())
}
fn count(d: &Dir, prefix: &Path, m: &Matcher) -> Result<usize> {
    let mut count = 0;
    for n in d.entries()? {
        let p = prefix.join(&n);
        if m.protected(&p) {
            count += 1;
            continue;
        }
        let md = d.metadata(n.as_os_str())?;
        if md.directory() {
            count += self::count(&d.child(n.as_os_str())?, &p, m)?;
        }
    }
    Ok(count)
}
