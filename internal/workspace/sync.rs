use super::{
    diff::changes,
    prepare::{read_entry, snapshot, Snapshot},
};
use crate::{policy::matcher::Matcher, security::paths::Dir};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::File,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedEntry {
    hash: [u8; 32],
    mode: u32,
    link_target: Option<PathBuf>,
}

impl From<&super::prepare::Entry> for ExpectedEntry {
    fn from(entry: &super::prepare::Entry) -> Self {
        Self {
            hash: entry.hash,
            mode: entry.mode,
            link_target: entry.link_target.clone(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum JournalRecord {
    #[serde(rename = "intent")]
    Intent {
        version: u32,
        path: PathBuf,
        original: Option<ExpectedEntry>,
        desired: Option<ExpectedEntry>,
    },
    #[serde(rename = "status")]
    Status { version: u32, status: String },
}

#[derive(Clone)]
struct RecoveryPlan {
    path: PathBuf,
    remove_current: bool,
    restore_original: bool,
}

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
    let _sync_lock = project_sync_lock(root_path, root)?;
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
        .prefix(".runboundary-recovery-")
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
        .mode(0o600)
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
            let intent = JournalRecord::Intent {
                version: 2,
                path: ch.path.clone(),
                original: baseline.get(&ch.path).map(ExpectedEntry::from),
                desired: after.get(&ch.path).map(ExpectedEntry::from),
            };
            writeln!(journal, "{}", serde_json::to_string(&intent)?)?;
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
        writeln!(
            journal,
            "{}",
            serde_json::to_string(&JournalRecord::Status {
                version: 2,
                status: "complete".to_owned(),
            })?
        )?;
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

/// Restore the pre-apply state from an interrupted version-2 transaction.
/// Every project and backup path is checked before the first mutation.
pub fn recover(
    root_path: &Path,
    root: &Dir,
    recovery_name: &Path,
    matcher: &Matcher,
) -> Result<bool> {
    let relative_name = if recovery_name.is_absolute() {
        recovery_name.strip_prefix(root_path).map_err(|_| {
            anyhow::anyhow!("recovery directory must be directly inside the selected project")
        })?
    } else {
        recovery_name
    };
    let name = relative_name
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid recovery directory name")?;
    if relative_name.components().count() != 1
        || !matches!(
            relative_name.components().next(),
            Some(Component::Normal(_))
        )
        || !valid_recovery_name(name)
    {
        bail!("recovery must name a direct .runboundary-recovery-* directory in the project");
    }
    let _sync_lock = project_sync_lock(root_path, root)?;
    let full_path = root_path.join(name);
    let metadata = std::fs::symlink_metadata(&full_path)
        .with_context(|| format!("cannot inspect recovery directory {full_path:?}"))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        bail!("recovery directory must be a private directory owned by the current user");
    }
    let recovery = root.child(std::ffi::OsStr::new(name))?;
    let identity = recovery.identity()?;
    if identity.dev != metadata.dev()
        || identity.ino != metadata.ino()
        || identity.mode != metadata.mode()
    {
        bail!("recovery directory changed while opening it");
    }
    let (bytes, journal_identity) = recovery.read_file("journal.jsonl", 16 * 1024 * 1024)?;
    if !journal_identity.regular()
        || journal_identity.links != 1
        || journal_identity.mode & 0o077 != 0
    {
        bail!("unsafe recovery journal");
    }
    let text = std::str::from_utf8(&bytes).context("recovery journal is not UTF-8")?;
    let complete_lines = if text.ends_with('\n') {
        text
    } else {
        text.rsplit_once('\n').map_or("", |(complete, _)| complete)
    };
    let mut intents = Vec::new();
    let mut seen = HashSet::new();
    let mut completed = false;
    let mut recovered = false;
    for line in complete_lines.lines().filter(|line| !line.is_empty()) {
        let record: JournalRecord = serde_json::from_str(line).with_context(|| {
            "recovery journal is unsupported or damaged; use the manual procedure in docs/recovery.md"
        })?;
        match record {
            JournalRecord::Intent {
                version,
                path,
                original,
                desired,
            } => {
                if version != 2 || !valid_relative_path(&path) || !seen.insert(path.clone()) {
                    bail!("invalid or duplicate path in recovery journal");
                }
                if matcher.protected(&path) {
                    bail!(
                        "recovery journal contains a protected path; refusing automatic recovery"
                    );
                }
                intents.push((path, original, desired));
            }
            JournalRecord::Status { version, status } => {
                if version != 2 || !matches!(status.as_str(), "complete" | "recovered") {
                    bail!("invalid status in recovery journal");
                }
                completed = status == "complete";
                recovered = status == "recovered";
            }
        }
    }
    if completed || recovered {
        return Ok(false);
    }
    let originals = recovery.child(std::ffi::OsStr::new("originals"))?;
    let mut plans = Vec::with_capacity(intents.len());
    for (path, original, desired) in intents.iter().rev() {
        let current = read_expected(root, path)?;
        let backup = read_expected(&originals, path)?;
        let plan = match original {
            Some(expected_original) => {
                if backup.as_ref().is_some_and(|actual| actual != expected_original) {
                    bail!("recovery original does not match journal for {path:?}");
                }
                if current.as_ref() == Some(expected_original) {
                    RecoveryPlan {
                        path: path.clone(),
                        remove_current: false,
                        restore_original: false,
                    }
                } else if current.is_none() {
                    if backup.is_none() {
                        bail!("both original and project file are missing for {path:?}");
                    }
                    RecoveryPlan {
                        path: path.clone(),
                        remove_current: false,
                        restore_original: true,
                    }
                } else if current.as_ref() == desired.as_ref() && desired.is_some() {
                    if backup.is_none() {
                        bail!("original backup is missing for changed path {path:?}");
                    }
                    RecoveryPlan {
                        path: path.clone(),
                        remove_current: true,
                        restore_original: true,
                    }
                } else {
                    bail!("project path {path:?} changed since interruption; preserve it and recover manually");
                }
            }
            None => match (current.as_ref(), desired.as_ref()) {
                (None, _) => RecoveryPlan {
                    path: path.clone(),
                    remove_current: false,
                    restore_original: false,
                },
                (Some(actual), Some(expected)) if actual == expected => RecoveryPlan {
                    path: path.clone(),
                    remove_current: true,
                    restore_original: false,
                },
                _ => bail!("project addition {path:?} changed since interruption; preserve it and recover manually"),
            },
        };
        plans.push(plan);
    }

    for plan in plans {
        if plan.remove_current {
            root.remove(&plan.path)?;
        }
        if plan.restore_original {
            root.ensure_parent(&plan.path)?;
            originals.rename(&plan.path, root, &plan.path)?;
        }
    }
    recovery.append_file(
        Path::new("journal.jsonl"),
        format!(
            "{}\n",
            serde_json::to_string(&JournalRecord::Status {
                version: 2,
                status: "recovered".to_owned(),
            })?
        )
        .as_bytes(),
    )?;
    Ok(true)
}

fn valid_recovery_name(name: &str) -> bool {
    name.strip_prefix(".runboundary-recovery-")
        .or_else(|| name.strip_prefix(".agentvault-recovery-"))
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn valid_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn read_expected(root: &Dir, path: &Path) -> Result<Option<ExpectedEntry>> {
    let components = path.components().collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("unsafe path in recovery journal");
    }
    let mut parent = root.child(std::ffi::OsStr::new("."))?;
    for component in &components[..components.len() - 1] {
        let Component::Normal(name) = component else {
            unreachable!()
        };
        match parent.child(name) {
            Ok(next) => parent = next,
            Err(error) if is_not_found(&error) => return Ok(None),
            Err(error) => return Err(error),
        }
    }
    let Component::Normal(name) = components[components.len() - 1] else {
        unreachable!()
    };
    let metadata = match parent.metadata(name) {
        Ok(metadata) => metadata,
        Err(error) if is_not_found(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.symlink() {
        let (target, after) = parent.read_link(Path::new(name))?;
        if after != metadata {
            bail!("recovery symlink changed while reading");
        }
        use std::os::unix::ffi::OsStrExt;
        Ok(Some(ExpectedEntry {
            hash: Sha256::digest(target.as_os_str().as_bytes()).into(),
            mode: 0o777,
            link_target: Some(target),
        }))
    } else {
        if !metadata.regular() || metadata.links != 1 {
            bail!("unsafe file type at recovery path {:?}", path);
        }
        let (bytes, after) = parent.read_file(Path::new(name), super::prepare::FILE_LIMIT)?;
        if after != metadata {
            bail!("recovery file changed while reading");
        }
        Ok(Some(ExpectedEntry {
            hash: Sha256::digest(bytes).into(),
            mode: 0o600 | (metadata.mode & 0o100),
            link_target: None,
        }))
    }
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .and_then(|error| error.raw_os_error())
        == Some(libc::ENOENT)
}

fn project_sync_lock(root_path: &Path, root: &Dir) -> Result<File> {
    let root_identity = root.identity()?;
    let recovery_parent = std::fs::symlink_metadata(root_path)?;
    if recovery_parent.dev() != root_identity.dev || recovery_parent.ino() != root_identity.ino {
        if !recovery_parent.is_dir()
            || recovery_parent.file_type().is_symlink()
            || recovery_parent.uid() != unsafe { libc::geteuid() }
            || recovery_parent.mode() & 0o077 != 0
        {
            bail!("recovery parent must be a private current-user-owned directory");
        }
        return Dir::open(root_path)?.lock(Path::new(".runboundary-sync.lock"));
    }
    match root.metadata(std::ffi::OsStr::new(".runboundary")) {
        Ok(metadata) if metadata.directory() && metadata.mode & 0o077 == 0 => {
            let state_path = root_path.join(".runboundary");
            let host_metadata = std::fs::symlink_metadata(&state_path)?;
            if host_metadata.file_type().is_symlink()
                || !host_metadata.is_dir()
                || host_metadata.uid() != unsafe { libc::geteuid() }
                || host_metadata.dev() != metadata.dev
                || host_metadata.ino() != metadata.ino
                || host_metadata.mode() != metadata.mode
            {
                bail!("unsafe RunBoundary project state directory");
            }
        }
        Ok(_) => bail!("RunBoundary project state directory must be private"),
        Err(error) if is_not_found(&error) => {
            root.mkdir(std::ffi::OsStr::new(".runboundary"))?;
        }
        Err(error) => return Err(error),
    }
    root.lock(Path::new(".runboundary/sync.lock"))
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use crate::policy::{config::Config, matcher::Matcher};
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn expected(bytes: &[u8], mode: u32) -> ExpectedEntry {
        ExpectedEntry {
            hash: Sha256::digest(bytes).into(),
            mode,
            link_target: None,
        }
    }

    fn write_intent(
        journal: &mut std::fs::File,
        path: &str,
        original: Option<ExpectedEntry>,
        desired: Option<ExpectedEntry>,
    ) {
        writeln!(
            journal,
            "{}",
            serde_json::to_string(&JournalRecord::Intent {
                version: 2,
                path: PathBuf::from(path),
                original,
                desired,
            })
            .unwrap()
        )
        .unwrap();
        journal.sync_all().unwrap();
    }

    fn setup_recovery(root: &Path) -> (PathBuf, std::fs::File) {
        let name = ".runboundary-recovery-test";
        let state = root.join(".runboundary");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(path.join("originals")).unwrap();
        std::fs::create_dir(path.join("staged")).unwrap();
        std::fs::set_permissions(
            path.join("originals"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(path.join("staged"), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let journal = std::fs::OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(path.join("journal.jsonl"))
            .unwrap();
        std::fs::set_permissions(
            path.join("journal.jsonl"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        (PathBuf::from(name), journal)
    }

    #[test]
    fn interrupted_apply_restores_modified_deleted_added_and_link_paths() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().canonicalize().unwrap();
        std::fs::write(root_path.join("modified.txt"), b"agent version").unwrap();
        std::fs::write(root_path.join("added.txt"), b"new file").unwrap();
        symlink("target-after", root_path.join("link.txt")).unwrap();
        let (recovery_name, mut journal) = setup_recovery(&root_path);
        let originals_path = root_path.join(&recovery_name).join("originals");
        std::fs::write(originals_path.join("modified.txt"), b"original version").unwrap();
        std::fs::write(originals_path.join("deleted.txt"), b"deleted original").unwrap();
        symlink("target-before", originals_path.join("link.txt")).unwrap();

        let link_before = ExpectedEntry {
            hash: Sha256::digest(b"target-before").into(),
            mode: 0o777,
            link_target: Some(PathBuf::from("target-before")),
        };
        let link_after = ExpectedEntry {
            hash: Sha256::digest(b"target-after").into(),
            mode: 0o777,
            link_target: Some(PathBuf::from("target-after")),
        };
        write_intent(
            &mut journal,
            "modified.txt",
            Some(expected(b"original version", 0o600)),
            Some(expected(b"agent version", 0o600)),
        );
        write_intent(
            &mut journal,
            "deleted.txt",
            Some(expected(b"deleted original", 0o600)),
            None,
        );
        write_intent(
            &mut journal,
            "added.txt",
            None,
            Some(expected(b"new file", 0o600)),
        );
        write_intent(
            &mut journal,
            "link.txt",
            Some(link_before),
            Some(link_after),
        );
        drop(journal);

        let root = Dir::open(&root_path).unwrap();
        let matcher = Matcher::new(&Config::defaults()).unwrap();
        assert!(recover(&root_path, &root, &recovery_name, &matcher).unwrap());
        assert_eq!(
            std::fs::read(root_path.join("modified.txt")).unwrap(),
            b"original version"
        );
        assert_eq!(
            std::fs::read(root_path.join("deleted.txt")).unwrap(),
            b"deleted original"
        );
        assert!(!root_path.join("added.txt").exists());
        assert_eq!(
            std::fs::read_link(root_path.join("link.txt")).unwrap(),
            PathBuf::from("target-before")
        );
        assert!(!recover(&root_path, &root, &recovery_name, &matcher).unwrap());
    }

    #[test]
    fn recovery_conflict_is_detected_before_any_project_path_changes() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().canonicalize().unwrap();
        std::fs::write(root_path.join("added.txt"), b"agent addition").unwrap();
        std::fs::write(root_path.join("modified.txt"), b"later user edit").unwrap();
        let (recovery_name, mut journal) = setup_recovery(&root_path);
        let originals = root_path.join(&recovery_name).join("originals");
        std::fs::write(originals.join("modified.txt"), b"original version").unwrap();
        write_intent(
            &mut journal,
            "added.txt",
            None,
            Some(expected(b"agent addition", 0o600)),
        );
        write_intent(
            &mut journal,
            "modified.txt",
            Some(expected(b"original version", 0o600)),
            Some(expected(b"agent version", 0o600)),
        );
        drop(journal);

        let root = Dir::open(&root_path).unwrap();
        let matcher = Matcher::new(&Config::defaults()).unwrap();
        assert!(recover(&root_path, &root, &recovery_name, &matcher).is_err());
        assert_eq!(
            std::fs::read(root_path.join("added.txt")).unwrap(),
            b"agent addition"
        );
        assert_eq!(
            std::fs::read(root_path.join("modified.txt")).unwrap(),
            b"later user edit"
        );
    }

    #[test]
    fn recovery_survives_every_interrupted_apply_operation_boundary() {
        #[derive(Clone, Copy)]
        enum Step {
            Intent(usize),
            Backup(usize),
            Install(usize),
        }

        let entries = [
            (
                "modified.txt",
                Some(expected(b"before", 0o600)),
                Some(expected(b"after", 0o600)),
                Some(b"before".as_slice()),
                Some(b"after".as_slice()),
            ),
            (
                "deleted.txt",
                Some(expected(b"delete me", 0o600)),
                None,
                Some(b"delete me".as_slice()),
                None,
            ),
            (
                "added.txt",
                None,
                Some(expected(b"new", 0o600)),
                None,
                Some(b"new".as_slice()),
            ),
            (
                "link.txt",
                Some(ExpectedEntry {
                    hash: Sha256::digest(b"before-target").into(),
                    mode: 0o777,
                    link_target: Some(PathBuf::from("before-target")),
                }),
                Some(ExpectedEntry {
                    hash: Sha256::digest(b"after-target").into(),
                    mode: 0o777,
                    link_target: Some(PathBuf::from("after-target")),
                }),
                Some(b"before-target".as_slice()),
                Some(b"after-target".as_slice()),
            ),
        ];
        let mut steps = Vec::new();
        for (index, (_, original, desired, _, _)) in entries.iter().enumerate() {
            steps.push(Step::Intent(index));
            if original.is_some() {
                steps.push(Step::Backup(index));
            }
            if desired.is_some() {
                steps.push(Step::Install(index));
            }
        }

        // Recreate each possible crash boundary, including the window after a
        // durable intent and before either rename, then require full rollback.
        for cut in 0..=steps.len() {
            let temp = tempfile::tempdir().unwrap();
            let root_path = temp.path().canonicalize().unwrap();
            let (recovery_name, mut journal) = setup_recovery(&root_path);
            let recovery_path = root_path.join(&recovery_name);
            let originals = recovery_path.join("originals");
            let staged = recovery_path.join("staged");
            let root = Dir::open(&root_path).unwrap();

            for (name, original, desired, before, after) in &entries {
                if let (Some(expected), Some(target)) = (original, before) {
                    if expected.link_target.is_some() {
                        symlink(std::str::from_utf8(target).unwrap(), root_path.join(name))
                            .unwrap();
                    } else {
                        std::fs::write(root_path.join(name), target).unwrap();
                    }
                }
                if let (Some(expected), Some(target)) = (desired, after) {
                    if expected.link_target.is_some() {
                        symlink(std::str::from_utf8(target).unwrap(), staged.join(name)).unwrap();
                    } else {
                        std::fs::write(staged.join(name), target).unwrap();
                    }
                }
            }

            for step in steps.iter().take(cut) {
                match *step {
                    Step::Intent(index) => {
                        let (name, original, desired, _, _) = &entries[index];
                        write_intent(&mut journal, name, original.clone(), desired.clone());
                    }
                    Step::Backup(index) => {
                        let (name, ..) = &entries[index];
                        root.rename(
                            Path::new(name),
                            &Dir::open(&originals).unwrap(),
                            Path::new(name),
                        )
                        .unwrap();
                    }
                    Step::Install(index) => {
                        let (name, ..) = &entries[index];
                        Dir::open(&staged)
                            .unwrap()
                            .rename(Path::new(name), &root, Path::new(name))
                            .unwrap();
                    }
                }
            }
            drop(journal);

            let matcher = Matcher::new(&Config::defaults()).unwrap();
            assert!(
                recover(&root_path, &root, &recovery_name, &matcher).unwrap(),
                "recovery failed at operation boundary {cut}"
            );
            assert_eq!(
                std::fs::read(root_path.join("modified.txt")).unwrap(),
                b"before"
            );
            assert_eq!(
                std::fs::read(root_path.join("deleted.txt")).unwrap(),
                b"delete me"
            );
            assert_eq!(
                std::fs::read(root_path.join("added.txt"))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::NotFound
            );
            assert_eq!(
                std::fs::read_link(root_path.join("link.txt")).unwrap(),
                PathBuf::from("before-target")
            );
        }
    }
}
