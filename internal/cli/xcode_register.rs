use crate::{
    policy::{config::Config, matcher::Matcher},
    security::{audit, paths::Dir},
    workspace::{diff, prepare, sync, xcode},
};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// This edits only the retained copy. The existing review/apply transaction
/// subsequently treats project metadata just like the other source changes.
pub fn execute(
    root: &Path,
    id: &str,
    project: &Path,
    discover: bool,
    files: &[PathBuf],
) -> Result<()> {
    let (record, _lock) = super::review::load(root, id)?;
    let matcher = Matcher::new(&Config::load(root)?)?;
    let out = Dir::open(&record.workspace)?;
    let before = prepare::snapshot(&out, &matcher, true)?;
    let files = if discover {
        diff::changes(&record.baseline, &before)
            .into_iter()
            .filter(|c| c.kind == "added")
            .map(|c| c.path)
            .collect::<Vec<_>>()
    } else {
        files.to_vec()
    };
    let pbx = project.join("project.pbxproj");
    if matcher.protected(project)
        || matcher.protected(&pbx)
        || project.extension().and_then(|s| s.to_str()) != Some("xcodeproj")
    {
        bail!("expected a permitted workspace-relative .xcodeproj directory");
    }
    let (bytes, _) = out.read_file(&pbx, 8 * 1024 * 1024).with_context(|| {
        format!("cannot read Xcode project metadata {pbx:?} in retained session {id:?}; --xcode-project must name a .xcodeproj directory relative to that workspace")
    })?;
    let text = std::str::from_utf8(&bytes)?;
    for file in &files {
        if matcher.protected(file) || !before.get(file).is_some_and(|e| e.link_target.is_none()) {
            bail!("registration requires a permitted regular file: {:?}", file);
        }
        if file
            .components()
            .any(|c| c.as_os_str().to_string_lossy().ends_with(".xcodeproj"))
        {
            bail!("cannot register Xcode project internals: {:?}", file);
        }
    }
    let (updated, count) = xcode::register(text, project, &files)?;
    if count == 0 {
        println!("No new navigator references needed.");
        return Ok(());
    }
    // Reuse the bounded copier and journaled synchronization instead of writing
    // through potentially attacker-controlled paths or truncating project files.
    let stage = prepare::prepare(&out, &matcher)?;
    if stage.baseline != before {
        bail!("retained workspace changed during registration; retry after stopping other editors");
    }
    let staged = Dir::open(stage.path())?;
    staged.remove(&pbx)?;
    staged.create(&pbx, updated.as_bytes(), before[&pbx].mode)?;
    let after = prepare::snapshot(&staged, &matcher, true)?;
    // Keep backups beside the workspace, outside both sandbox access and the
    // source snapshot. Recovery metadata must never become a project addition.
    let private_parent = record
        .workspace
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing private session parent"))?;
    let recovery = sync::apply(private_parent, &out, &staged, &before, &after, &matcher)?;
    Dir::open(private_parent)?.sync()?;
    audit::log(
        root,
        "xcode_files_registered",
        "navigator references updated in retained copy; no target membership or host project edits",
    )?;
    println!(
        "Registered {count} file(s) in the retained Xcode navigator; target membership unchanged."
    );
    println!("Close and reopen the retained workspace in Xcode to refresh it. Stop Xcode editing before registration.");
    if let Some(path) = recovery {
        println!("Metadata recovery originals: {path:?}");
    }
    println!("Original project unchanged. Review: runb diff {id}");
    println!("Approve after review: runb apply {id}");
    Ok(())
}
