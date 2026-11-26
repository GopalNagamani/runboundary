use crate::{
    policy::matcher::Matcher,
    security::paths::{Dir, Identity},
};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
pub const FILE_LIMIT: u64 = 64 * 1024 * 1024;
const MAX_DEPTH: usize = 128;
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub hash: [u8; 32],
    pub mode: u32,
    pub identity: Identity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<PathBuf>,
}
pub type Snapshot = BTreeMap<PathBuf, Entry>;
pub struct Workspace {
    pub temp: TempDir,
    directory: PathBuf,
    pub baseline: Snapshot,
    pub excluded: usize,
}
impl Workspace {
    pub fn path(&self) -> &Path {
        &self.directory
    }
}
#[derive(Default)]
struct CopySize {
    bytes: u128,
    entries: u128,
}

impl CopySize {
    /// Count logical file sizes because the copier does not preserve sparse layouts.
    fn scan(&mut self, src: &Dir, prefix: &Path, matcher: &Matcher) -> Result<()> {
        if prefix.components().count() > MAX_DEPTH {
            bail!("workspace traversal limit exceeded");
        }
        for name in src.entries()? {
            let path = prefix.join(&name);
            if matcher.protected(&path) {
                continue;
            }
            let entry = src.metadata(name.as_os_str())?;
            self.entries += 1;
            if entry.directory() {
                self.scan(&src.child(name.as_os_str())?, &path, matcher)?;
            } else if entry.symlink() || (entry.regular() && entry.links == 1) {
                self.bytes += u128::try_from(entry.size).context("invalid workspace entry size")?;
            } else {
                bail!("unsafe symlink, special file, or hard link at {:?}", path);
            }
        }
        Ok(())
    }

    fn check_space(&self, available: u128, block_size: u128) -> Result<()> {
        const MIB: u128 = 1024 * 1024;
        // Allow for block rounding and directory or file metadata per entry.
        let needed = self.bytes + self.entries * block_size * 2;
        if needed > available {
            bail!(
                "insufficient disk space for the temporary workspace: about {} MiB needed, {} MiB available; free space or set TMPDIR to a volume with more space",
                needed.div_ceil(MIB),
                available / MIB,
            );
        }
        Ok(())
    }
}

pub fn prepare(root: &Dir, matcher: &Matcher) -> Result<Workspace> {
    let temp = tempfile::Builder::new()
        .prefix("runboundary-work-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let directory = temp.path().join("workspace");
    Dir::open(temp.path())?.mkdir(std::ffi::OsStr::new("workspace"))?;
    let dest = Dir::open(&directory)?;
    let mut estimate = CopySize::default();
    estimate.scan(root, Path::new(""), matcher)?;
    let (available, block_size) = dest.filesystem_space()?;
    estimate.check_space(available, block_size)?;
    let mut baseline = Snapshot::new();
    let mut excluded = 0;
    walk(
        root,
        Some(&dest),
        Path::new(""),
        matcher,
        false,
        &mut baseline,
        &mut excluded,
    )
    .context("cannot copy the project into temporary workspace storage")?;
    validate_links(&baseline, matcher)?;
    // Defer symlink creation until every permitted regular target is copied.
    // Targets are never followed by the copier.
    for (path, entry) in &baseline {
        if let Some(target) = &entry.link_target {
            dest.create_link(path, target)?;
        }
    }
    Ok(Workspace {
        temp,
        directory,
        baseline,
        excluded,
    })
}
pub fn snapshot(root: &Dir, matcher: &Matcher, reject_protected: bool) -> Result<Snapshot> {
    let mut out = Snapshot::new();
    let mut excluded = 0;
    walk(
        root,
        None,
        Path::new(""),
        matcher,
        reject_protected,
        &mut out,
        &mut excluded,
    )?;
    validate_links(&out, matcher)?;
    Ok(out)
}
#[allow(clippy::too_many_arguments)]
fn walk(
    src: &Dir,
    dest: Option<&Dir>,
    prefix: &Path,
    matcher: &Matcher,
    reject: bool,
    out: &mut Snapshot,
    excluded: &mut usize,
) -> Result<()> {
    if prefix.components().count() > MAX_DEPTH || out.len() > 100_000 {
        bail!("workspace traversal limit exceeded");
    }
    let before = src.identity()?;
    for name in src.entries()? {
        let path = prefix.join(&name);
        if matcher.protected(&path) {
            if reject {
                bail!(
                    "sandbox output contains protected path {:?}; synchronization rejected",
                    path
                );
            }
            *excluded += 1;
            continue;
        }
        let m = src.metadata(name.as_os_str())?;
        if m.directory() {
            let child = src.child(name.as_os_str())?;
            if child.identity()? != m {
                bail!("directory changed before traversal");
            }
            if let Some(d) = dest {
                d.mkdir(name.as_os_str())?;
                let to = d.child(name.as_os_str())?;
                walk(&child, Some(&to), &path, matcher, reject, out, excluded)?;
            } else {
                walk(&child, None, &path, matcher, reject, out, excluded)?;
            }
            if src.metadata(name.as_os_str())? != m {
                bail!("directory changed during traversal");
            }
        } else if m.symlink() {
            let (target, identity) = src.read_link(&name)?;
            if identity != m {
                bail!("symlink changed during traversal");
            }
            use std::os::unix::ffi::OsStrExt;
            let bytes = target.as_os_str().as_bytes();
            out.insert(
                path,
                Entry {
                    hash: Sha256::digest(bytes).into(),
                    mode: 0o777,
                    identity,
                    link_target: Some(target),
                },
            );
        } else {
            if !m.regular() || m.links != 1 {
                bail!("unsafe symlink, special file, or hard link at {:?}", path);
            }
            let (bytes, identity) = src.read_file(&name, FILE_LIMIT)?;
            if identity != m {
                bail!("file changed during traversal");
            }
            if let Some(d) = dest {
                d.create(&name, &bytes, 0o600 | (m.mode & 0o100))?;
            }
            out.insert(
                path,
                Entry {
                    hash: Sha256::digest(&bytes).into(),
                    mode: 0o600 | (m.mode & 0o100),
                    identity,
                    link_target: None,
                },
            );
        }
    }
    if src.identity()? != before {
        bail!("directory permissions or entries changed while scanning");
    }
    Ok(())
}

/// Restrict links to the npm-style form: leading ../ components followed by
/// normal names. Reject interior a/../ traversal so missing/excluded intermediate
/// directories cannot change the kernel's interpretation of a normalized path.
fn link_destination(path: &Path, target: &Path) -> Result<PathBuf> {
    use std::path::Component;
    let mut destination = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing link parent"))?
        .to_owned();
    let mut named = false;
    for component in target.components() {
        match component {
            Component::ParentDir if !named => {
                if !destination.pop() {
                    bail!("symlink escapes workspace");
                }
            }
            Component::Normal(name) => {
                named = true;
                destination.push(name);
            }
            _ => bail!("absolute or complex symlink target rejected"),
        }
    }
    if !named {
        bail!("symlink target must name a regular file");
    }
    Ok(destination)
}
fn validate_links(snapshot: &Snapshot, matcher: &Matcher) -> Result<()> {
    for (path, entry) in snapshot {
        let Some(target) = &entry.link_target else {
            continue;
        };
        let destination = link_destination(path, target)?;
        for ancestor in destination
            .ancestors()
            .filter(|p| !p.as_os_str().is_empty())
        {
            if matcher.protected(ancestor) {
                bail!("symlink {:?} targets a protected path", path);
            }
        }
        let regular = snapshot.get(&destination).is_some_and(|e| {
            e.link_target.is_none() && e.identity.regular() && e.identity.links == 1
        });
        if !regular {
            bail!("symlink {:?} must target a copied regular file; directory links, chains and missing targets are rejected", path);
        }
    }
    Ok(())
}

/// Read reviewed entry bytes without following a link, for staging/conflict checks.
pub fn read_entry(dir: &Dir, path: &Path, entry: &Entry) -> Result<(Vec<u8>, Identity)> {
    if let Some(expected) = &entry.link_target {
        use std::os::unix::ffi::OsStrExt;
        let (target, identity) = dir.read_link(path)?;
        if &target != expected {
            bail!("symlink target changed after review");
        }
        Ok((target.as_os_str().as_bytes().to_vec(), identity))
    } else {
        dir.read_file(path, FILE_LIMIT)
    }
}

#[cfg(test)]
mod copy_size_tests {
    use super::*;
    use crate::policy::config::Config;

    #[test]
    fn disk_estimate_skips_protected_files_before_counting_bytes() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join("src")).unwrap();
        std::fs::write(project.path().join("src/source.txt"), b"abc").unwrap();
        let protected = std::fs::File::create(project.path().join(".env")).unwrap();
        protected.set_len(2 * 1024 * 1024 * 1024).unwrap();

        let root = Dir::open(project.path()).unwrap();
        let matcher = Matcher::new(&Config::defaults()).unwrap();
        let mut estimate = CopySize::default();
        estimate.scan(&root, Path::new(""), &matcher).unwrap();

        assert_eq!(estimate.bytes, 3);
        assert_eq!(estimate.entries, 2);
        assert!(estimate.check_space(16_387, 4096).is_ok());
        let error = estimate.check_space(16_386, 4096).unwrap_err();
        assert!(error.to_string().contains("insufficient disk space"));
    }
}
