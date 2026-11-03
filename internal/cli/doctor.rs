use crate::{
    policy::{config::Config, matcher::Matcher},
    sandbox::backend::Backend,
    security::paths::Dir,
    workspace::prepare,
};
use anyhow::Result;
use std::path::Path;
pub fn execute(root: &Path, agent: &str, auth: &[String], auth_file: Option<&Path>) -> Result<()> {
    println!("AgentVault Security Check\n");
    let config = Config::load(root)?;
    let backend = Backend::select(root, &config)?;
    println!(
        "[PASS] Host and configured {} backend match",
        backend.name()
    );
    let matcher = Matcher::new(&config)?;
    println!("[PASS] Protected patterns and fail-closed policy validated");
    let dir = Dir::open(root)?;
    let work = prepare::prepare(&dir, &matcher)?;
    let env = backend.environment(&config, auth, work.path())?;
    println!("[PASS] Environment filtering enabled");
    backend.probe(root, work.path(), &env)?;
    println!(
        "[PASS] Actual {} sandbox startup and filesystem probe verified",
        backend.name()
    );
    println!(
        "[PASS] Filesystem isolation probe succeeded; {} protected paths/subtrees excluded",
        work.excluded
    );
    if !backend.tool_roots().is_empty() {
        println!("[INFO] {} explicit read-only SDK trees configured; use tools --check for executable checks", backend.tool_roots().len());
    }
    backend.resolve(agent)?;
    if let Some(source) = auth_file {
        crate::security::codex_auth::validate_agent(agent)?;
        let home = work
            .path()
            .parent()
            .ok_or_else(|| anyhow::anyhow!("missing session parent"))?
            .join("sandbox-home");
        crate::security::codex_auth::import(source, &home)?;
        println!("[PASS] Approved ChatGPT credential file validated (provider session not tested)");
    }
    backend.cleanup_private_dirs(work.path(), &env)?;
    println!("[PASS] Requested executable available in trusted runtime");
    if auth_file.is_some() {
        println!("[INFO] ChatGPT login selected; credentials are discarded after the session");
    } else if auth.is_empty() {
        println!("[INFO] No provider credential imported; agent/provider handles authentication if needed");
    } else {
        println!("[PASS] Approved provider credential present (provider login not tested)");
    }
    println!("\nLocal sandbox checks passed. Provider authentication and agent-version compatibility require an actual session.");
    Ok(())
}
