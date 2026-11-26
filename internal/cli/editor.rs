use crate::security::paths::Dir;
use anyhow::{bail, Context, Result};
use std::{
    fs::File,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
};

const ACTIVE_RECORD: &str = "active-project.json";
const ACTIVE_LOCK: &str = "active-project.lock";

pub(super) fn require_macos() -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("opening an editor is currently supported on macOS");
    }
    Ok(())
}

/// Keep the lock alive only while this workspace can be opened as an active session.
pub(super) fn register(project: &Dir, session: &Path) -> Result<File> {
    let identity = project.identity()?;
    let session = Dir::open(session)?;
    let lock = session.lock(Path::new(ACTIVE_LOCK))?;
    session.create(
        Path::new(ACTIVE_RECORD),
        &serde_json::to_vec(&[identity.dev, identity.ino])?,
        0o600,
    )?;
    Ok(lock)
}

pub(super) fn execute(
    root: &Path,
    app: &str,
    file: Option<&Path>,
    session: Option<&str>,
) -> Result<()> {
    require_macos()?;
    let temp = std::env::temp_dir().canonicalize()?;
    let workspace = active_workspace(root, &temp, session)?;
    open(&workspace, app, file)
}

fn active_workspace(root: &Path, temp: &Path, session: Option<&str>) -> Result<PathBuf> {
    let project = Dir::open(root)?.identity()?;
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(temp)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|name| name.strip_prefix("runboundary-work-"))
        else {
            continue;
        };
        if session.is_some_and(|requested| requested != id) {
            continue;
        }
        let workspace = entry.path().join("workspace");
        if super::review::validate_workspace(root, id, &workspace).is_err() {
            continue;
        }
        let Ok(directory) = Dir::open(&entry.path()) else {
            continue;
        };
        let Some(identity) = directory
            .read_file(ACTIVE_RECORD, 256)
            .ok()
            .and_then(|(data, _)| serde_json::from_slice::<[u64; 2]>(&data).ok())
        else {
            continue;
        };
        if identity != [project.dev, project.ino] {
            continue;
        }
        // A surviving directory after a crash or a retained workspace has no
        // live owner of this lock. Only a currently held lock counts.
        if let Err(error) = directory.lock(Path::new(ACTIVE_LOCK)) {
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == ErrorKind::WouldBlock)
            {
                matches.push((id.to_owned(), workspace));
            }
        }
    }

    match matches.as_slice() {
        [(_, workspace)] => Ok(workspace.clone()),
        [] => bail!(
            "no matching active RunBoundary session for this project; start runb run AGENT first"
        ),
        _ => {
            let mut ids: Vec<_> = matches.iter().map(|(id, _)| id.as_str()).collect();
            ids.sort_unstable();
            bail!(
                "multiple active sessions: {}; choose one with --session ID",
                ids.join(", ")
            );
        }
    }
}

fn xcode_file(workspace: &Dir) -> Result<PathBuf> {
    let mut workspaces = Vec::new();
    let mut projects = Vec::new();
    for name in workspace.entries()? {
        let matches = match name.extension().and_then(|ext| ext.to_str()) {
            Some("xcworkspace") => &mut workspaces,
            Some("xcodeproj") => &mut projects,
            _ => continue,
        };
        if workspace
            .metadata(name.as_os_str())
            .is_ok_and(|meta| meta.directory())
        {
            matches.push(name);
        }
    }
    let candidates = if workspaces.is_empty() {
        projects
    } else {
        workspaces
    };
    match candidates.as_slice() {
        [file] => Ok(file.clone()),
        [] => bail!("no Xcode workspace or project at the workspace root; specify its relative path with --file (or --editor-file with run)"),
        _ => bail!("multiple Xcode workspaces or projects; specify the relative path with --file (or --editor-file with run)"),
    }
}

fn target(workspace: &Path, xcode: bool, file: Option<&Path>) -> Result<PathBuf> {
    let directory = Dir::open(workspace)?;
    let detected;
    let file = match (file, xcode) {
        (Some(file), _) => file,
        (None, true) => {
            detected = xcode_file(&directory)?;
            &detected
        }
        (None, false) => return Ok(workspace.to_path_buf()),
    };
    if file.as_os_str().is_empty()
        || !file
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        bail!("editor file must be a relative path inside the workspace");
    }
    if xcode
        && !matches!(
            file.extension().and_then(|ext| ext.to_str()),
            Some("xcworkspace" | "xcodeproj")
        )
    {
        bail!("Xcode requires a .xcworkspace or .xcodeproj path");
    }
    let (parent, name) = directory.parent(file)?;
    let meta = parent.metadata(&name)?;
    if !meta.directory() && (!meta.regular() || xcode) {
        bail!("editor target must be a regular file or directory inside the workspace");
    }
    Ok(workspace.join(file))
}

pub(super) fn open(workspace: &Path, app: &str, file: Option<&Path>) -> Result<()> {
    require_macos()?;
    let app = match app.to_ascii_lowercase().as_str() {
        "vscode" | "code" => "Visual Studio Code",
        "cursor" => "Cursor",
        "xcode" => "Xcode",
        _ => app,
    };
    let target = target(workspace, app == "Xcode", file)?;
    let status = Command::new("/usr/bin/open")
        .args(["-a", app])
        .arg(&target)
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("could not launch {app}"))?;
    if !status.success() {
        bail!("could not open {target:?} in {app} ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn active_lookup_rejects_other_projects_and_stale_sessions() {
        let temp = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let other_project = tempfile::tempdir().unwrap();
        let root = Dir::open(project.path()).unwrap();
        let session = |id| {
            let parent = temp.path().join(format!("runboundary-work-{id}"));
            std::fs::create_dir(&parent).unwrap();
            let directory = Dir::open(&parent).unwrap();
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            directory.mkdir(std::ffi::OsStr::new("workspace")).unwrap();
            let lock = register(&root, &parent).unwrap();
            (parent.join("workspace"), lock)
        };
        let (first, first_lock) = session("first");
        assert_eq!(
            active_workspace(project.path(), temp.path(), None).unwrap(),
            first
        );
        assert!(active_workspace(other_project.path(), temp.path(), None).is_err());
        let (second, _second_lock) = session("second");
        assert!(active_workspace(project.path(), temp.path(), None)
            .unwrap_err()
            .to_string()
            .contains("first, second"));
        assert_eq!(
            active_workspace(project.path(), temp.path(), Some("first")).unwrap(),
            first
        );
        drop(first_lock);
        assert_eq!(
            active_workspace(project.path(), temp.path(), None).unwrap(),
            second
        );
        assert!(active_workspace(project.path(), temp.path(), Some("first")).is_err());
    }

    #[test]
    fn xcode_prefers_the_workspace_and_rejects_symlink_targets() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path();
        std::fs::create_dir(root.join("App.xcodeproj")).unwrap();
        std::fs::create_dir(root.join("App.xcworkspace")).unwrap();
        std::os::unix::fs::symlink(root.join("App.xcworkspace"), root.join("link.xcworkspace"))
            .unwrap();

        assert_eq!(
            target(root, true, None).unwrap(),
            root.join("App.xcworkspace")
        );
        assert!(target(root, true, Some(Path::new("link.xcworkspace"))).is_err());
        assert!(target(root, false, Some(Path::new("../outside"))).is_err());
        std::fs::create_dir(root.join("Other.xcworkspace")).unwrap();
        assert!(target(root, true, None).is_err());
        assert_eq!(
            target(root, true, Some(Path::new("Other.xcworkspace"))).unwrap(),
            root.join("Other.xcworkspace")
        );
    }
}
