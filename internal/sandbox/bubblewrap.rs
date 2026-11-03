use super::{mounts, process};
use anyhow::{bail, Context, Result};
use std::{collections::BTreeMap, path::Path, process::Command};
pub fn command(
    root: &Path,
    work: &Path,
    env: &BTreeMap<String, String>,
    executable: &Path,
    args: &[String],
) -> Result<Command> {
    command_with_home(root, work, env, executable, args, None)
}
pub fn command_with_home(
    root: &Path,
    work: &Path,
    env: &BTreeMap<String, String>,
    executable: &Path,
    args: &[String],
    home: Option<&Path>,
) -> Result<Command> {
    command_with_roots(root, work, env, executable, args, home, &[])
}
pub fn command_with_roots(
    root: &Path,
    work: &Path,
    env: &BTreeMap<String, String>,
    executable: &Path,
    args: &[String],
    home: Option<&Path>,
    roots: &[std::path::PathBuf],
) -> Result<Command> {
    crate::platform::linux::require()?;
    let bwrap = mounts::resolve("bwrap")?;
    let mut c = Command::new(bwrap);
    c.env_clear();
    // Credentials go through execve environment, never through the bwrap argv.
    c.envs(env);
    c.args([
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--disable-userns",
        "--assert-userns-disabled",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--hostname",
        "agentvault",
    ]);
    mounts::configure(&mut c, root)?;
    c.args([
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/home",
        "--perms",
        "0700",
        "--tmpfs",
        "/home/agent",
    ]);
    if let Some(home) = home {
        c.arg("--bind").arg(home).arg("/home/agent");
    }
    for sdk in roots {
        c.arg("--ro-bind").arg(sdk).arg(sdk);
    }
    c.arg("--bind").arg(work).arg("/workspace");
    c.args(["--chdir", "/workspace", "--remount-ro", "/", "--"]);
    c.arg(executable).args(args);
    process::harden(&mut c);
    Ok(c)
}
pub fn probe(root: &Path, work: &Path, env: &BTreeMap<String, String>) -> Result<()> {
    probe_with_roots(root, work, env, None, &[])
}
pub fn probe_with_roots(
    root: &Path,
    work: &Path,
    env: &BTreeMap<String, String>,
    home: Option<&Path>,
    roots: &[std::path::PathBuf],
) -> Result<()> {
    let shell = mounts::resolve("sh")?;
    // Host path passed positionally, never interpolated as shell code.
    let script = r#"
set -eu
fail() { printf 'AgentVault isolation check failed: %s\n' "$1" >&2; exit 1; }
[ "$HOME" = /home/agent ] || fail private-home-location
[ ! -e "$1" ] || fail original-project-hidden
[ ! -e /root/.ssh/id_rsa ] || fail host-ssh-key-hidden
[ ! -e /root/.aws/credentials ] || fail host-aws-credentials-hidden
[ ! -e /var/run/docker.sock ] || fail docker-socket-hidden
[ ! -e /run/docker.sock ] || fail run-docker-socket-hidden
[ ! -e /workspace/.env ] || fail project-env-excluded
[ ! -e /workspace/.env.production ] || fail production-env-excluded
[ -z "${SSH_AUTH_SOCK+x}" ] || fail ssh-agent-environment-filtered
[ -z "${LD_PRELOAD+x}" ] || fail loader-environment-filtered
grep -q '^NoNewPrivs:[[:space:]]*1' /proc/self/status || fail no-new-privileges
grep -q '^CapEff:[[:space:]]*0000000000000000' /proc/self/status || fail capabilities-dropped
printf probe > /workspace/.agentvault-probe || fail workspace-writable
rm /workspace/.agentvault-probe || fail workspace-cleanup
printf probe > "$HOME/probe" || fail private-home-writable
rm "$HOME/probe" || fail private-home-cleanup
printf AGENTVAULT_PROBE_OK
"#;
    let args = vec![
        "-c".into(),
        script.into(),
        "agentvault-probe".into(),
        root.to_string_lossy().into_owned(),
    ];
    // Local isolation checks need no provider credential. Keep all other
    // variables identical so the probe still detects a broken environment filter.
    let mut probe_env = env.clone();
    probe_env.remove("OPENAI_API_KEY");
    probe_env.remove("ANTHROPIC_API_KEY");
    let output = command_with_roots(root, work, &probe_env, &shell, &args, home, roots)?
        .output()
        .context(
            "sandbox process could not start; executable startup or pre-exec hardening failed",
        )?;
    if !output.status.success() || output.stdout != b"AGENTVAULT_PROBE_OK" {
        let diagnostic = backend_diagnostic(&output.stderr, env);
        bail!("sandbox startup or isolation probe failed (status {}); backend diagnostic: {}. Required controls remain enabled. No agent launched",output.status,diagnostic);
    }
    Ok(())
}

pub(super) fn backend_diagnostic(stderr: &[u8], env: &BTreeMap<String, String>) -> String {
    let mut text = String::from_utf8_lossy(stderr).into_owned();
    // Redact before truncating, so a token crossing the limit cannot leak a prefix.
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"] {
        if let Some(value) = env.get(key).filter(|value| !value.is_empty()) {
            text = text.replace(value, "[REDACTED]");
        }
    }
    let truncated = text.chars().count() > 4096;
    text = text.chars().take(4096).collect();
    if text.trim().is_empty() {
        text = "no backend stderr; probe did not return its expected success marker".into();
    }
    if truncated {
        text.push_str(" [truncated]");
    }
    // Escape control sequences before presenting backend output in a terminal.
    format!("{text:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_diagnostics_redact_before_truncating_and_escape_controls() {
        let mut env = BTreeMap::new();
        env.insert("OPENAI_API_KEY".into(), "SYNTHETIC-OPENAI-TOKEN".into());
        env.insert(
            "ANTHROPIC_API_KEY".into(),
            "SYNTHETIC-ANTHROPIC-TOKEN".into(),
        );
        let stderr = format!(
            "\u{1b}[31m{} SYNTHETIC-OPENAI-TOKEN SYNTHETIC-ANTHROPIC-TOKEN",
            "x".repeat(4080)
        );
        let diagnostic = backend_diagnostic(stderr.as_bytes(), &env);
        assert!(!diagnostic.contains("SYNTHETIC"));
        assert!(!diagnostic.contains('\u{1b}'));
        assert!(diagnostic.contains("truncated"));
    }

    #[test]
    fn startup_errors_and_empty_diagnostics_are_actionable() {
        let env = BTreeMap::new();
        assert!(backend_diagnostic(b"bwrap: namespace denied", &env).contains("namespace denied"));
        assert!(backend_diagnostic(b"", &env).contains("success marker"));
    }
}
