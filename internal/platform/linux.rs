use anyhow::{bail, Result};
pub fn require() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("the Bubblewrap backend requires Linux; configure seatbelt on macOS. No agent was launched");
    }
    if unsafe { libc::geteuid() } == 0 {
        bail!("run AgentVault as an unprivileged user, not root");
    }
    Ok(())
}
