use super::{config::Config, matcher::Matcher};
use anyhow::{bail, Result};
pub fn validate(c: &Config) -> Result<()> {
    if c.version != 1
        || !c.sandbox.enabled
        || !["bubblewrap", "seatbelt"].contains(&c.sandbox.backend.as_str())
        || !c.sandbox.fail_closed
    {
        bail!("version 1 requires enabled bubblewrap or seatbelt with fail_closed: true");
    }
    if c.sandbox.backend != "seatbelt" && !c.sandbox.runtime_roots.is_empty() {
        bail!("runtime_roots is supported only by the seatbelt backend");
    }
    if c.environment.inherit_all {
        bail!("inherit_all must be false");
    }
    if !c.audit.enabled || !c.audit.redact_secrets {
        bail!("audit and redaction must remain enabled");
    }
    for name in &c.environment.allow {
        if !["PATH", "TERM", "LANG", "LC_ALL"].contains(&name.as_str()) {
            bail!("environment.allow accepts only PATH, TERM, LANG, LC_ALL; approve provider credentials using --auth-env");
        }
    }
    c.toolchains.validate_syntax()?;
    Matcher::new(c)?;
    Ok(())
}
