//! Reopen a retained session under the configured OS sandbox, without approval.
use crate::{
    policy::{config::Config, matcher::Matcher},
    sandbox::{backend::Backend, process},
    security::{audit, paths::Dir},
    workspace::{diff, prepare},
};
use anyhow::{Context, Result};
use std::path::Path;

pub fn execute(
    root: &Path,
    id: &str,
    ports: &[u16],
    args: &[String],
    allow_network_listen: bool,
) -> Result<i32> {
    let (record, _lock) = super::review::load(root, id)?;
    let config = Config::load(root)?;
    let matcher = Matcher::new(&config)?;
    let backend = Backend::select(root, &config)?;

    // Reject unsafe/protected output before granting any runtime access.
    let workspace = record.workspace.canonicalize()?;
    let out = Dir::open(&workspace)?;
    let before = prepare::snapshot(&out, &matcher, true)?;
    let (executable, command_args) = command_plan(&backend, &workspace, args)?;
    // environment() creates new private directories with O_EXCL semantics. A
    // stale home after an interrupted session refuses startup rather than being reused.
    let env = backend.environment(&config, &[], &workspace)?;
    let result = (|| -> Result<i32> {
        println!("Verifying preview sandbox isolation...");
        backend.probe(root, &workspace, &env)?;
        audit::log(root, "preview_isolation_verified", backend.name())?;
        let mut command = backend.preview_command(
            root,
            &workspace,
            &env,
            &executable,
            &command_args,
            allow_network_listen,
        )?;
        if allow_network_listen && backend.name() == "seatbelt" {
            println!("TCP listener access explicitly enabled. macOS does not enforce loopback or port restrictions; configure the app to bind 127.0.0.1. A server using other interfaces may be reachable from your network.");
        }
        println!(
            "Sandbox preflight: Verified\nStarting preview; original project stays unchanged."
        );
        for port in ports {
            println!("Requested preview address: http://127.0.0.1:{port} (availability depends on the app)");
        }
        if backend.name() == "bubblewrap" {
            println!("Linux shares the host network; neither --port nor omission of --allow-network-listen restricts listening ports. Configure your app to bind 127.0.0.1.");
        }
        println!("Stop a foreground preview with Ctrl-C, then review and approve the session separately.");
        audit::log(
            root,
            "preview_launch_requested",
            if allow_network_listen {
                "explicit TCP listener approval; no provider credentials imported; no synchronization approval"
            } else {
                "no TCP listener approval; no provider credentials imported; no synchronization approval"
            },
        )?;
        let status = process::interactive(&mut command)?;
        let code = process::exit_code(status);
        audit::log(root, "preview_exited", &format!("exit_code={code}"))?;
        Ok(code)
    })();
    // Cleanup and output validation also run after process/spawn errors.
    let cleanup = backend.cleanup_private_dirs(&workspace, &env);
    let after = prepare::snapshot(&out, &matcher, true);
    cleanup.context("preview private-directory cleanup failed; session was not applied")?;
    let after = after.context(
        "unsafe preview output rejected; session retained but cannot be applied until repaired",
    )?;
    println!("\nPreview changes (filenames only):");
    let changes = diff::changes(&before, &after);
    if changes.is_empty() {
        println!("No additional file changes.");
    }
    for change in changes {
        println!("  {} {:?}", change.kind, change.path);
    }
    println!("All session changes remain unapplied. Review: agentvault review {id} --diff");
    println!("Approve after review: agentvault review {id} --apply");
    // The original baseline is intentionally unchanged: review includes agent
    // edits AND build/test artifacts produced during this preview.
    if result.is_err() {
        let _ = audit::log(
            root,
            "preview_failed",
            "startup or process failure; no fallback or apply",
        );
    }
    result
}

/// Workspace programs are untrusted: execute them only through a trusted shell
/// inside the backend, never by spawning them on the host.
pub fn command_plan(
    backend: &Backend,
    workspace: &Path,
    args: &[String],
) -> Result<(std::path::PathBuf, Vec<String>)> {
    use std::path::Component;
    let requested = args.first().context("missing preview command")?;
    if let Some(relative) = requested.strip_prefix("./") {
        let relative = Path::new(relative);
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            anyhow::bail!("unsafe workspace executable path");
        }
        let dir = Dir::open(workspace)?;
        let (parent, name) = dir.parent(relative)?;
        let meta = parent.metadata(&name)?;
        if !meta.regular() || meta.links != 1 || meta.mode & 0o100 == 0 {
            anyhow::bail!("workspace executable must be a single-linked regular file with owner execute permission");
        }
        let executable = if backend.name() == "bubblewrap" {
            Path::new("/workspace").join(relative)
        } else {
            workspace.join(relative)
        };
        let mut wrapped = vec![
            "-c".into(),
            r#"exec "$@""#.into(),
            "agentvault-workspace-command".into(),
            executable
                .to_str()
                .context("workspace executable path must be UTF-8")?
                .into(),
        ];
        wrapped.extend_from_slice(&args[1..]);
        Ok((backend.resolve("/bin/sh")?, wrapped))
    } else {
        Ok((backend.resolve(requested)?, args[1..].to_vec()))
    }
}
