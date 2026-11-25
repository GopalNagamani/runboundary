use crate::{
    policy::matcher::Matcher,
    security::paths::{Dir, Identity},
};
use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
pub const FILE_LIMIT: u64 = 64 * 1024 * 1024;
pub const TOTAL_LIMIT: u64 = 512 * 1024 * 1024;
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
pub fn prepare(root: &Dir, matcher: &Matcher) -> Result<Workspace> {
    let temp = tempfile::Builder::new()
        .prefix("runboundary-work-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let directory = temp.path().join("workspace");
    Dir::open(temp.path())?.mkdir(std::ffi::OsStr::new("workspace"))?;
    let dest = Dir::open(&directory)?;
    let mut baseline = Snapshot::new();
    let mut excluded = 0;
    let mut total = 0;
    walk(
        root,
        Some(&dest),
        Path::new(""),
        matcher,
        false,
        &mut baseline,
        &mut excluded,
        &mut total,
    )?;
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
    let mut total = 0;
    walk(
        root,
        None,
        Path::new(""),
        matcher,
        reject_protected,
        &mut out,
        &mut excluded,
        &mut total,
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
    total: &mut u64,
) -> Result<()> {
    if prefix.components().count() > 128 || out.len() > 100_000 {
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
                walk(
                    &child,
                    Some(&to),
                    &path,
                    matcher,
                    reject,
                    out,
                    excluded,
                    total,
                )?;
            } else {
                walk(&child, None, &path, matcher, reject, out, excluded, total)?;
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
            *total += bytes.len() as u64;
            if *total > TOTAL_LIMIT {
                bail!("workspace exceeds 512 MiB limit");
            }
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
            *total += bytes.len() as u64;
            if *total > TOTAL_LIMIT {
                bail!("workspace exceeds 512 MiB limit");
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
