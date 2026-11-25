//! One-time, explicit approval of host-owned adapter manifests.
use crate::security::{auth_adapter::Adapter, paths::Dir};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use std::{
    io::{self, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Approve and save a built-in or custom adapter for future runs in any project.
    Setup {
        /// One or more agents with built-in profiles. Custom adapters support one agent per command.
        #[arg(required = true, num_args = 1..)]
        agents: Vec<String>,
        /// Use an existing private adapter manifest for another agent.
        #[arg(long)]
        adapter: Option<PathBuf>,
    },
    /// Remove saved approval; does not delete host credentials or cached programs.
    Remove { agent: String },
}
fn basename(agent: &str) -> Result<&str> {
    let name = Path::new(agent)
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid agent executable")?;
    if name.is_empty()
        || Path::new(name)
            .components()
            .any(|p| !matches!(p, Component::Normal(_)))
        || name.chars().any(char::is_control)
    {
        bail!("invalid agent name");
    }
    Ok(name)
}
fn host_home() -> Result<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME").context("host HOME is missing")?);
    if !home.is_absolute() {
        bail!("host HOME must be absolute");
    }
    Ok(home.canonicalize()?)
}
fn profile_path(agent: &str) -> Result<PathBuf> {
    Ok(host_home()?
        .join(".config/runboundary/auth")
        .join(format!("{}.json", basename(agent)?)))
}
pub(super) fn codex_file(
    agent: &str,
    chatgpt: bool,
    explicit: Option<PathBuf>,
) -> Result<Option<PathBuf>> {
    if !chatgpt {
        return Ok(explicit);
    }
    crate::security::codex_auth::validate_agent(agent)?;
    let home = PathBuf::from(std::env::var_os("HOME").context("host HOME is missing")?);
    if !home.is_absolute() {
        bail!("host HOME must be absolute");
    }
    Ok(Some(home.join(".codex/auth.json")))
}
pub fn selected(
    agent: &str,
    explicit: Option<PathBuf>,
    other_auth: bool,
    disabled: bool,
) -> Result<Option<PathBuf>> {
    if explicit.is_some() || other_auth || disabled {
        return Ok(explicit);
    }
    let path = profile_path(agent)?;
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            // Validate approval before reporting or attempting sandbox startup.
            Adapter::load(&path, agent)?;
            println!(
                "Using saved authentication adapter for {:?}.",
                basename(agent)?
            );
            Ok(Some(path))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}
fn store() -> Result<Dir> {
    let home = host_home()?;
    let dir = Dir::open(&home)?;
    dir.ensure_parent(Path::new(".config/runboundary/auth/profile.json"))?;
    let path = home.join(".config/runboundary/auth");
    for folder in [home.join(".config/runboundary"), path.clone()] {
        let m = std::fs::symlink_metadata(folder)?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            bail!("saved adapter directories must be private and owned by the current user");
        }
    }
    Dir::open(&path)
}
pub fn execute(command: &AuthCommand) -> Result<()> {
    match command {
        AuthCommand::Remove { agent } => {
            let path = profile_path(agent)?;
            let root = Dir::open(Path::new("/"))?;
            root.remove(path.strip_prefix("/")?)?;
            println!("Saved approval removed. Host login and cache files unchanged.");
        }
        AuthCommand::Setup { agents, adapter } => {
            let mut seen = std::collections::HashSet::new();
            for agent in agents {
                if agent != basename(agent)? {
                    bail!("setup requires executable basenames");
                }
                if !seen.insert(agent.as_str()) {
                    bail!("agent {agent:?} was listed more than once");
                }
            }
            if adapter.is_some() && agents.len() != 1 {
                bail!(
                    "--adapter can be used with one agent; batch setup supports built-in profiles"
                );
            }

            // Build and validate every profile before asking for approval or writing any.
            let mut prepared = Vec::with_capacity(agents.len());
            for agent in agents {
                let bytes = if let Some(path) = adapter {
                    Adapter::approved_manifest(path, agent)?
                } else {
                    match agent.as_str() {
                        "freebuff" => Adapter::freebuff_manifest(&host_home()?)?,
                        "hermes" => Adapter::hermes_manifest(&host_home()?)?,
                        _ => bail!("no built-in profile for {agent:?}; supply --adapter /absolute/path/manifest.json (one agent per command)"),
                    }
                };
                let profile_path = profile_path(agent)?;
                match std::fs::symlink_metadata(&profile_path) {
                    Ok(_) => bail!("saved approval already exists for {agent}; use auth remove before replacing it"),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
                let parsed = Adapter::from_manifest(&bytes, agent)?;
                prepared.push((agent, bytes, parsed));
            }

            if prepared
                .iter()
                .any(|(agent, _, _)| agent.as_str() == "hermes")
            {
                println!("Hermes Nous Portal profile filters auth.json and model configuration only. It does not approve the Hermes application or Python runtime. Home-installed launchers remain unsupported until their runtime is installed in an approved location.");
            }
            println!("Approve these files for future RunBoundary runs across all projects:");
            for (agent, _, parsed) in &prepared {
                println!("{agent}:");
                for line in parsed.approval_lines() {
                    println!("  {line}");
                }
            }
            println!("Copies are readable by each agent, discarded after each session, and never written back to the host. Cached programs may still check for updates.");
            print!("Save all approvals? [y/N] ");
            io::stdout().flush()?;
            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                println!("Cancelled; no approvals saved.");
                return Ok(());
            }
            let dir = store()?;
            let mut created = Vec::new();
            for (agent, bytes, _) in &prepared {
                let filename = format!("{agent}.json");
                if let Err(error) = dir.create(Path::new(&filename), bytes, 0o600) {
                    for created_name in created.iter().rev() {
                        let _ = dir.remove(Path::new(created_name));
                    }
                    let _ = dir.sync();
                    return Err(error).context(
                        "could not save all approvals; attempted to remove files created by this command",
                    );
                }
                created.push(filename);
            }
            dir.sync()?;
            for (agent, _, _) in prepared {
                println!("Saved. Run: runb run {agent}");
            }
        }
    }
    Ok(())
}
