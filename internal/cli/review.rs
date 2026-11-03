use crate::{
    policy::{config::Config, matcher::Matcher},
    security::{audit, paths::Dir},
    workspace::{
        diff,
        prepare::{self, Snapshot},
        sync,
    },
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    version: u32,
    root_device: u64,
    root_inode: u64,
    pub(super) workspace: PathBuf,
    pub(super) baseline: Snapshot,
}
pub fn retain(root: &Path, workspace: PathBuf, baseline: Snapshot) -> Result<String> {
    let root_dir = Dir::open(root)?;
    let identity = root_dir.identity()?;
    let name = workspace
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|x| x.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid session path"))?;
    let id = name
        .strip_prefix("agentvault-work-")
        .ok_or_else(|| anyhow::anyhow!("invalid session id"))?
        .to_owned();
    let record = Record {
        version: 1,
        root_device: identity.dev,
        root_inode: identity.ino,
        workspace,
        baseline,
    };
    let path = PathBuf::from(format!(".agentvault/review-{id}.json"));
    root_dir.create(&path, &serde_json::to_vec(&record)?, 0o600)?;
    Ok(id)
}
pub(super) fn load(root: &Path, id: &str) -> Result<(Record, std::fs::File)> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("invalid session id");
    }
    let dir = Dir::open(root)?;
    let lock = dir.lock(&PathBuf::from(format!(".agentvault/session-{id}.lock")))?;
    let record_path = format!(".agentvault/review-{id}.json");
    let (bytes, _) = dir
        .read_file(&record_path, 16 * 1024 * 1024)
        .with_context(|| {
            format!(
                "cannot load pending session {id:?} in project {root:?} from {record_path:?}; \
             an applied session has no pending review record. Check the project and session ID. \
             For sandbox registration, use a new retained session from agentvault run; \
             an old workspace directory alone cannot restore review/apply authorization"
            )
        })?;
    let record: Record = serde_json::from_slice(&bytes)?;
    let identity = dir.identity()?;
    if record.version != 1
        || record.root_device != identity.dev
        || record.root_inode != identity.ino
    {
        bail!("review record belongs to a different project");
    }
    validate_workspace(root, id, &record.workspace)?;
    Ok((record, lock))
}

fn validate_workspace(root: &Path, id: &str, workspace: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let parent = workspace
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing workspace parent"))?;
    if !workspace.is_absolute()
        || workspace.file_name() != Some(std::ffi::OsStr::new("workspace"))
        || parent.file_name() != Some(std::ffi::OsStr::new(&format!("agentvault-work-{id}")))
    {
        bail!("invalid retained workspace location");
    }
    // Permit macOS's system /var alias only through canonical parent lookup;
    // the workspace and its private immediate parent must themselves be real dirs.
    for path in [parent, workspace] {
        let meta = std::fs::symlink_metadata(path)
            .with_context(|| format!("retained session {id:?} directory unavailable: {path:?}; temporary workspace may have been removed"))?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            bail!("retained workspace must have private, current-user-owned directories without symlinks");
        }
    }
    let canonical = workspace.canonicalize()?;
    if canonical.starts_with(root) || root.starts_with(&canonical) {
        bail!("retained workspace overlaps original project");
    }
    // Refuse symlinks in the canonical traversal used for subsequent access.
    let fs = Dir::open(Path::new("/"))?;
    let (parent, name) = fs.parent(canonical.strip_prefix("/")?)?;
    parent.child(&name)?;
    Ok(())
}

pub fn execute(root: &Path, id: &str, apply: bool, show_diff: bool) -> Result<()> {
    let (record, _lock) = load(root, id)?;
    let dir = Dir::open(root)?;
    let config = Config::load(root)?;
    let matcher = Matcher::new(&config)?;
    let out = Dir::open(&record.workspace)?;
    let reviewed = prepare::snapshot(&out, &matcher, true)?;
    for ch in diff::changes(&record.baseline, &reviewed) {
        println!("{} {:?}", ch.kind, ch.path);
        if show_diff {
            if record.baseline.contains_key(&ch.path) {
                print_entry("-", &dir, &ch.path, &record.baseline[&ch.path])?;
            }
            if reviewed.contains_key(&ch.path) {
                print_entry("+", &out, &ch.path, &reviewed[&ch.path])?;
            }
        }
    }
    if apply {
        if let Some(recovery) =
            sync::apply(root, &dir, &out, &record.baseline, &reviewed, &matcher)?
        {
            audit::log(
                root,
                "sync_applied",
                "explicit review --apply approval; recovery originals retained",
            )?;
            println!("Applied. Recovery originals: {:?}", recovery);
        }
        dir.remove(&PathBuf::from(format!(".agentvault/review-{id}.json")))?;
        println!(
            "Retained workspace remains at {:?}; remove it after review.",
            record.workspace.parent()
        );
    } else {
        println!("Approve with: agentvault review {id} --apply");
    }
    Ok(())
}
fn print_entry(prefix: &str, dir: &Dir, path: &Path, entry: &prepare::Entry) -> Result<()> {
    if let Some(target) = &entry.link_target {
        // Verify identity/type without following; escape target text for terminals.
        prepare::read_entry(dir, path, entry)?;
        println!("{prefix} [symlink -> {target:?}]");
        return Ok(());
    }
    let (bytes, _) = dir.read_file(path, prepare::FILE_LIMIT)?;
    if bytes.len() > 64 * 1024 {
        println!("{prefix} [file exceeds 64 KiB preview limit]");
        return Ok(());
    }
    match std::str::from_utf8(&bytes) {
        Ok(text) => {
            for line in text.lines() {
                println!("{prefix} {}", serde_json::to_string(line)?);
            }
        }
        Err(_) => println!("{prefix} [binary file]"),
    }
    Ok(())
}
