use crate::{
    policy::{config::Config, matcher::Matcher},
    sandbox::{backend::Backend, process},
    security::{audit, paths::Dir},
    workspace::{diff, prepare, sync},
};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
pub fn execute(
    root: &Path,
    apply: bool,
    auth: &[String],
    agent: &[String],
    auth_file: Option<&Path>,
) -> Result<i32> {
    execute_with_adapter(root, apply, auth, agent, auth_file, None)
}
pub fn execute_with_adapter(
    root: &Path,
    apply: bool,
    auth: &[String],
    agent: &[String],
    auth_file: Option<&Path>,
    adapter_file: Option<&Path>,
) -> Result<i32> {
    execute_with_editor(root, apply, auth, agent, auth_file, adapter_file, None)
}

pub(super) fn execute_with_editor(
    root: &Path,
    apply: bool,
    auth: &[String],
    agent: &[String],
    auth_file: Option<&Path>,
    adapter_file: Option<&Path>,
    editor: Option<(&str, Option<&Path>)>,
) -> Result<i32> {
    if editor.is_some() {
        super::editor::require_macos()?;
    }
    if adapter_file.is_some() && (auth_file.is_some() || !auth.is_empty()) {
        bail!("authentication modes conflict");
    }
    let adapter = adapter_file
        .map(|p| {
            crate::security::auth_adapter::Adapter::load(
                p,
                agent.first().context("missing agent executable")?,
            )
        })
        .transpose()?;
    let config = Config::load(root)?;
    let backend = Backend::select(root, &config)?;
    let matcher = Matcher::new(&config)?;
    let requested = agent.first().context("missing agent executable")?;
    let exe = backend.resolve(requested).with_context(|| {
        if Path::new(requested).file_name().is_some_and(|n| n == "hermes") {
            "Hermes runtime unavailable in approved installations; its login adapter does not approve ~/.local/bin, ~/.hermes/hermes-agent, or the bundled Python runtime"
        } else { "agent executable unavailable in approved runtimes" }
    })?;
    println!(
        "RunBoundary v{}\n\nPreparing isolated workspace...",
        env!("CARGO_PKG_VERSION")
    );
    let dir = Dir::open(root)?;
    let work = prepare::prepare(&dir, &matcher)?;
    if auth_file.is_some() {
        crate::security::codex_auth::validate_agent(&agent[0])?;
        if !auth.is_empty() {
            bail!("authentication modes conflict");
        }
    }
    let mut env = backend.environment(&config, auth, work.path())?;
    if auth_file.is_some() {
        crate::security::codex_auth::configure(&mut env);
    }
    if let Some(adapter) = &adapter {
        adapter.configure(&mut env);
    }
    let (entrypoint, arguments) = process::agent_entrypoint_with_auth(
        &agent[0],
        &exe,
        &agent[1..],
        &env,
        auth_file.is_some(),
    )?;
    audit::log(
        root,
        "policy_validated",
        "mandatory exclusions; filtered environment; network enabled",
    )?;
    let cleanup_work = work.path().to_owned();
    let result = (|| -> Result<i32> {
        println!("Applying security policy...\nVerifying filesystem isolation...");
        backend.probe(root, work.path(), &env)?;
        audit::log(root, "isolation_probe_passed", backend.name())?;
        if let Some(adapter) = &adapter {
            adapter.import(
                &work
                    .path()
                    .parent()
                    .context("missing session parent")?
                    .join("sandbox-home"),
            )?;
            audit::log(
                root,
                "adapter_files_imported",
                "explicit adapter file approval; private copies discarded after session",
            )?;
            println!("Approved adapter files copied into disposable home.");
        }
        if let Some(source) = auth_file {
            let home = work
                .path()
                .parent()
                .context("missing session parent")?
                .join("sandbox-home");
            crate::security::codex_auth::import(source, &home)?;
            println!("Approved ChatGPT login copied into disposable sandbox home.");
            audit::log(root, "chatgpt_credential_imported", "explicit file approval; no host configuration imported; provider session not verified")?;
        }
        if auth_file.is_none()
            && auth.iter().any(|name| name == "OPENAI_API_KEY")
            && Path::new(&agent[0]).file_name().and_then(|n| n.to_str()) == Some("codex")
        {
            println!("Authenticating Codex inside sandbox...");
            let mut login = backend.command(
                root,
                work.path(),
                &env,
                &exe,
                &[
                    "-c".into(),
                    "cli_auth_credentials_store=\"file\"".into(),
                    "login".into(),
                    "--with-api-key".into(),
                ],
            )?;
            if let Err(error) = process::authenticate_codex(&mut login, &env) {
                backend.cleanup_private_dirs(work.path(), &env)?;
                return Err(error);
            }
            audit::log(
                root,
                "agent_login_completed",
                "Codex API-key login command succeeded; model request not verified",
            )?;
        }
        let mut command = backend.command(root, work.path(), &env, &entrypoint, &arguments)?;
        let active = if cfg!(target_os = "macos") {
            match super::editor::register(&dir, work.temp.path()) {
                Ok(lock) => Some(lock),
                Err(error) => {
                    eprintln!("RunBoundary: could not register live editor access: {error:#}");
                    None
                }
            }
        } else {
            None
        };
        if let Some((app, file)) = editor {
            super::editor::open(work.path(), app, file)?;
        }
        println!("\nProtected paths/subtrees excluded: {}\nSandbox preflight: Verified\nStarting sandboxed agent...",work.excluded);
        if active.is_some() {
            println!("Open the live copy from another terminal with: runb open EDITOR");
        }
        audit::log(root, "launch_requested", backend.name())?;
        let status = process::interactive(&mut command);
        drop(active);
        let status = status?;
        let code = process::exit_code(status);
        audit::log(root, "process_exited", &format!("exit_code={code}"))?;
        backend.cleanup_private_dirs(work.path(), &env)?;
        let out = Dir::open(work.path())?;
        let after = match prepare::snapshot(&out, &matcher, true) {
            Ok(s) => s,
            Err(e) => {
                audit::log(root, "sync_rejected", "unsafe or protected sandbox output")?;
                let saved = work.temp.keep();
                bail!(
                    "output rejected; untrusted workspace retained at {:?}: {}",
                    saved,
                    e
                );
            }
        };
        let changes = diff::changes(&work.baseline, &after);
        println!("\nChange summary (content is not printed):");
        let mut possible_secrets = false;
        for ch in &changes {
            println!("  {} {:?}", ch.kind, ch.path);
            if let Some(entry) = after.get(&ch.path) {
                let (bytes, identity) = prepare::read_entry(&out, &ch.path, entry)?;
                let hash: [u8; 32] = Sha256::digest(&bytes).into();
                if identity != entry.identity || hash != entry.hash {
                    bail!("file changed during secret scan: {:?}", ch.path);
                }
                possible_secrets |=
                    crate::security::secret_scan::redact_text(&String::from_utf8_lossy(&bytes)).1;
            }
        }
        if possible_secrets {
            println!("Review warning: possible credential-like content was detected in changed files; use `runb diff SESSION` to inspect redacted content. The scanner is heuristic and may miss secrets.");
        }
        if changes.is_empty() {
            println!("No file changes.");
            return Ok(code);
        }
        if apply && code == 0 {
            match sync::apply(root, &dir, &out, &work.baseline, &after, &matcher) {
                Ok(Some(recovery)) => {
                    println!("Changes applied. Recovery originals: {:?}", recovery)
                }
                Ok(None) => {}
                Err(e) => {
                    let saved = work.temp.keep();
                    return Err(e).with_context(|| format!("workspace retained at {:?}", saved));
                }
            }
            audit::log(
                root,
                "sync_applied",
                "explicit --apply approval; journal and recovery originals retained",
            )?;
        } else {
            let saved = work.temp.keep();
            let workspace = saved.join("workspace");
            let id = super::review::retain(root, workspace.clone(), work.baseline)?;
            println!(
                "Changes retained at {:?}. Host files were not modified.",
                workspace
            );
            println!("Preview: runb preview {id} COMMAND [ARGS...]");
            println!("Review: runb diff {id}");
            println!("Approve: runb apply {id}");
            audit::log(
                root,
                "workspace_retained",
                "no approval or nonzero agent exit",
            )?;
        }
        Ok(code)
    })();
    if result.is_err() {
        let _ = backend.cleanup_private_dirs(&cleanup_work, &env);
        let _ = audit::log(
            root,
            "session_failed",
            "sandbox initialization, execution, or synchronization failed; no fallback",
        );
    }
    result
}
