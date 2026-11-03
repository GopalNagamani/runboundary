use crate::policy::config::Config;
use anyhow::{bail, Result};
use std::collections::BTreeMap;
pub const SAFE_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
pub fn build(config: &Config, auth: &[String]) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    out.insert("PATH".into(), SAFE_PATH.into());
    out.insert("HOME".into(), "/home/agent".into());
    out.insert("TMPDIR".into(), "/tmp".into());
    for name in &config.environment.allow {
        if name == "PATH" {
            continue;
        }
        if let Ok(value) = std::env::var(name) {
            if value.len() > 256 || value.chars().any(char::is_control) {
                bail!("invalid terminal or locale variable");
            }
            out.insert(name.clone(), value);
        }
    }
    for name in auth {
        if !["OPENAI_API_KEY", "ANTHROPIC_API_KEY"].contains(&name.as_str()) {
            bail!("only OPENAI_API_KEY and ANTHROPIC_API_KEY may be approved");
        }
        let value = std::env::var(name)
            .map_err(|_| anyhow::anyhow!("approved credential variable is missing"))?;
        if value.is_empty() {
            bail!("approved credential variable is empty");
        }
        out.insert(name.clone(), value);
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filters_and_fixed_path() {
        let e = build(&Config::defaults(), &[]).unwrap();
        assert_eq!(e["PATH"], SAFE_PATH);
        assert!(!e.contains_key("SSH_AUTH_SOCK"));
        assert!(!e.contains_key("OPENAI_API_KEY"));
        assert!(!e.contains_key("LD_PRELOAD"));
    }
    #[test]
    fn arbitrary_auth_rejected() {
        assert!(build(&Config::defaults(), &["AWS_SECRET_ACCESS_KEY".into()]).is_err());
    }
}
