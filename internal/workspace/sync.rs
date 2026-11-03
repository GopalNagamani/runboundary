use super::{
    diff::changes,
    prepare::{read_entry, snapshot, Snapshot},
};
use crate::{policy::matcher::Matcher, security::paths::Dir};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::{io::Write, path::Path};

/// Explicit --apply is required by the caller. Keep recovery originals after success too.
/// Multi-file commit is journaled, not globally atomic; no claim of crash atomicity.
pub fn apply(
    root_path: &Path,
    root: &Dir,
    work: &Dir,
    baseline: &Snapshot,
    reviewed: &Snapshot,
    matcher: &Matcher,
) -> Result<Option<std::path::PathBuf>> {
    let now = snapshot(root, matcher, false)?;
    if &now != baseline {
        bail!("host project changed since preparation; refusing synchronization");
    }
    let after = snapshot(work, matcher, true)?;
    if &after != reviewed {
        bail!("sandbox output changed after review");
    }
    let delta = changes(baseline, &after);
    if delta.is_empty() {
        return Ok(None);
    }
    let recovery = tempfile::Builder::new()
        .prefix(".agentvault-recovery-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(root_path)?;
    let path = recovery.keep();
    root.sync()?;
    let backup = Dir::open(&path)?;
    backup.mkdir(std::ffi::OsStr::new("originals"))?;
    backup.mkdir(std::ffi::OsStr::new("staged"))?;
    let originals = backup.child(std::ffi::OsStr::new("originals"))?;
    let staged = backup.child(std::ffi::OsStr::new("staged"))?;
    let mut journal = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.join("journal.jsonl"))?;
    backup.sync()?;
    let mut committed = Vec::new();
    let operation = (|| -> Result<()> {
        for ch in &delta {
            if matcher.protected(&ch.path) {
                bail!("protected synchronization path");
            }
            if let Some(e) = after.get(&ch.path) {
                let (bytes, _) = read_entry(work, &ch.path, e)?;
                let hash: [u8; 32] = Sha256::digest(&bytes).into();
                if hash != e.hash {
                    bail!("output changed before staging");
                }
                staged.ensure_parent(&ch.path)?;
                if let Some(target) = &e.link_target {
                    staged.create_link(&ch.path, target)?;
                } else {
                    staged.create(&ch.path, &bytes, e.mode)?;
                }
            }
        }
        for ch in &delta {
            root.ensure_parent(&ch.path)?;
            let exists = baseline.contains_key(&ch.path);
            // Record intent durably BEFORE moving either file.
            writeln!(
                journal,
                "{}",
                serde_json::json!({"path":ch.path,"kind":ch.kind,"original":exists})
            )?;
            journal.sync_all()?;
            if exists {
                let b = &baseline[&ch.path];
                let (bytes, identity) = read_entry(root, &ch.path, b)?;
                let hash: [u8; 32] = Sha256::digest(&bytes).into();
                if identity != b.identity || hash != b.hash {
                    bail!("host file changed before commit");
                }
                originals.ensure_parent(&ch.path)?;
                root.rename(&ch.path, &originals, &ch.path)?;
            } else {
                let (d, n) = root.parent(&ch.path)?;
                match d.metadata(&n) {
                    Ok(_) => bail!("addition conflicts with existing host path"),
                    Err(e)
                        if e.downcast_ref::<std::io::Error>()
                            .and_then(|x| x.raw_os_error())
                            == Some(libc::ENOENT) => {}
                    Err(e) => return Err(e),
                }
            }
            committed.push((ch.path.clone(), exists, false));
            if after.contains_key(&ch.path) {
                staged.rename(&ch.path, root, &ch.path)?;
                committed.last_mut().unwrap().2 = true;
            }
        }
        writeln!(journal, "{{\"status\":\"complete\"}}")?;
        journal.sync_all()?;
        Ok(())
    })();
    if let Err(error) = operation {
        let mut rollback_errors = Vec::new();
        for (p, had_original, installed) in committed.iter().rev() {
            if *installed {
                let matches_staged = read_entry(root, p, &after[p])
                    .map(|(bytes, _)| {
                        let hash: [u8; 32] = Sha256::digest(bytes).into();
                        after.get(p).is_some_and(|e| e.hash == hash)
                    })
                    .unwrap_or(false);
                if !matches_staged {
                    rollback_errors.push(format!(
                        "refused to remove changed rollback path {:?}; restore originals manually",
                        p
                    ));
                    continue;
                }
                if let Err(e) = root.remove(p) {
                    rollback_errors.push(e.to_string());
                    continue;
                }
            }
            if *had_original {
                if let Err(e) = originals.rename(p, root, p) {
                    rollback_errors.push(e.to_string());
                }
            }
        }
        return Err(error).with_context(||format!("sync interrupted; recovery journal and originals at {:?}; rollback errors: {:?}. Stop editing; follow docs/recovery.md before retrying",path,rollback_errors));
    }
    Ok(Some(path))
}
