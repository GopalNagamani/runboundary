//! Explicit, bounded import of file-backed ChatGPT authentication only.
use super::paths::Dir;
use anyhow::{bail, Context, Result};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, ffi::OsStr, os::unix::fs::MetadataExt, path::Path};

pub fn validate_agent(agent: &str) -> Result<()> {
    if Path::new(agent).file_name() != Some(OsStr::new("codex")) {
        bail!("--codex-auth-file is only supported for Codex");
    }
    Ok(())
}

// Error messages intentionally omit JSON parser details and credential values.
fn filtered(bytes: &[u8]) -> Result<Vec<u8>> {
    let parsed: Value = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid Codex authentication JSON; contents withheld"))?;
    if parsed.get("auth_mode").and_then(Value::as_str) != Some("chatgpt")
        || parsed.get("OPENAI_API_KEY").is_some_and(|v| !v.is_null())
    {
        bail!("expected a ChatGPT login, without an API key");
    }
    let tokens = parsed
        .get("tokens")
        .and_then(Value::as_object)
        .context("ChatGPT login has no token object")?;
    let mut selected = Map::new();
    for name in ["id_token", "access_token", "refresh_token", "account_id"] {
        let value = tokens
            .get(name)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && v.len() <= 65536 && !v.chars().any(char::is_control))
            .context("ChatGPT login has missing or invalid credential fields")?;
        selected.insert(name.into(), Value::String(value.into()));
    }
    let mut out = serde_json::json!({"auth_mode":"chatgpt", "tokens":selected});
    if let Some(refresh) = parsed.get("last_refresh").and_then(Value::as_str) {
        if refresh.len() > 128 || refresh.chars().any(char::is_control) {
            bail!("invalid login refresh timestamp");
        }
        out["last_refresh"] = Value::String(refresh.into());
    }
    Ok(serde_json::to_vec(&out)?)
}

pub fn import(source: &Path, private_home: &Path) -> Result<()> {
    // Walk every component through openat/O_NOFOLLOW. In particular, never
    // canonicalize an attacker-controlled credential path before opening it.
    if !source.is_absolute() {
        bail!("credential file path must be absolute");
    }
    let relative = source.strip_prefix("/")?;
    let root = Dir::open(Path::new("/"))?;
    let (parent, name) = root.parent(relative)?;
    let owner = std::fs::symlink_metadata(source)?;
    if owner.uid() != unsafe { libc::geteuid() } {
        bail!("credential file must belong to the current user");
    }
    let (bytes, identity) = parent.read_file(Path::new(&name), 262144)?;
    if identity.mode & 0o077 != 0 || identity.ino != owner.ino() || identity.dev != owner.dev() {
        bail!("credential file must be private (chmod 600), stable and single-linked");
    }
    let bytes = filtered(&bytes)?;
    let home = Dir::open(private_home)?;
    home.mkdir(OsStr::new(".codex"))?;
    home.child(OsStr::new(".codex"))?
        .create(Path::new("auth.json"), &bytes, 0o600)?;
    Ok(())
}

pub fn configure(env: &mut BTreeMap<String, String>) {
    env.remove("OPENAI_API_KEY");
    env.remove("ANTHROPIC_API_KEY");
    env.insert("CODEX_HOME".into(), format!("{}/.codex", env["HOME"]));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fake() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"auth_mode":"chatgpt","tokens":{"id_token":"fake-id","access_token":"fake-access","refresh_token":"fake-refresh","account_id":"fake-account","unrelated":"excluded"},"unrelated":"excluded"})).unwrap()
    }
    #[test]
    fn import_is_narrow_private_and_does_not_change_source() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().canonicalize().unwrap().join("auth.json");
        std::fs::write(&source, fake()).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        let home = tempfile::tempdir().unwrap();
        import(&source, home.path()).unwrap();
        let output = std::fs::read(home.path().join(".codex/auth.json")).unwrap();
        assert!(!String::from_utf8_lossy(&output).contains("excluded"));
        assert_eq!(std::fs::read(source).unwrap(), fake());
        assert_eq!(
            std::fs::metadata(home.path().join(".codex/auth.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
    }
    #[test]
    fn unsafe_sources_and_wrong_auth_are_rejected_without_contents() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().canonicalize().unwrap().join("auth.json");
        std::fs::write(&source, fake()).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o644)).unwrap();
        let home = tempfile::tempdir().unwrap();
        assert!(import(&source, home.path()).is_err());
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&source, temp.path().join("link")).unwrap();
        assert!(import(
            &temp.path().canonicalize().unwrap().join("link"),
            home.path()
        )
        .is_err());
        std::fs::hard_link(&source, temp.path().join("hard")).unwrap();
        assert!(import(&source, home.path()).is_err());
        assert!(filtered(br#"{"auth_mode":"apikey","OPENAI_API_KEY":"fake"}"#).is_err());
        assert!(!filtered(b"SECRET_INVALID_JSON")
            .unwrap_err()
            .to_string()
            .contains("SECRET"));
    }
}
