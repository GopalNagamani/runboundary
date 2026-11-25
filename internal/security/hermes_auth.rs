//! Minimal Hermes Nous Portal credential/config projection; never import other providers.
use anyhow::{bail, Result};
use serde_json::{json, Map, Value};
pub fn filter_auth(bytes: &[u8]) -> Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid Hermes authentication JSON; contents withheld"))?;
    if value.get("version").and_then(Value::as_u64) != Some(1) {
        bail!("unsupported Hermes authentication store version");
    }
    let nous = value
        .get("providers")
        .and_then(|p| p.get("nous"))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Hermes store has no Nous Portal provider; log into Nous Portal with Hermes first"
            )
        })?;
    let mut selected = Map::new();
    for key in [
        "access_token",
        "refresh_token",
        "token_type",
        "client_id",
        "scope",
        "obtained_at",
        "expires_at",
        "expires_in",
        "portal_base_url",
        "inference_base_url",
        "agent_key",
        "agent_key_id",
        "agent_key_expires_at",
        "agent_key_expires_in",
        "agent_key_reused",
        "agent_key_obtained_at",
        "auth_method",
        "account_tier",
        "anon_token",
        "user_id",
        "org_id",
        "welcome_claim",
    ] {
        if let Some(value) = nous.get(key) {
            if !(value.is_string() || value.is_number() || value.is_boolean() || value.is_null()) {
                bail!("invalid Nous Portal credential field; contents withheld");
            }
            selected.insert(key.into(), value.clone());
        }
    }
    let has_token = ["access_token", "anon_token"].iter().any(|key| {
        selected
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
    });
    if !has_token {
        bail!("Nous Portal account/guest credential missing; log in with Hermes first");
    }
    // Force normal TLS validation; do not import TLS overrides or custom CA paths.
    Ok(serde_json::to_vec(
        &json!({"version":1,"active_provider":"nous","providers":{"nous":selected}}),
    )?)
}
pub fn filter_config(bytes: &[u8]) -> Result<Vec<u8>> {
    let value: Value = serde_yaml::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid Hermes model configuration; contents withheld"))?;
    let model = value
        .get("model")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("Hermes model configuration missing"))?;
    if model
        .get("provider")
        .and_then(Value::as_str)
        .is_some_and(|s| !["nous", "auto"].contains(&s))
    {
        bail!("Hermes configuration selects another provider; select Nous Portal first");
    }
    let name = model
        .get("default")
        .or_else(|| model.get("model"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control))
        .ok_or_else(|| anyhow::anyhow!("Hermes default model missing or invalid"))?;
    // Only provider/model survive. Never forward hooks, commands, environment,
    // tool definitions, MCP servers, API keys, endpoints, or arbitrary settings.
    Ok(serde_yaml::to_string(&json!({"model":{"provider":"nous","default":name}}))?.into_bytes())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_nous_credentials_and_model_survive() {
        let input = br#"{"version":1,"providers":{"nous":{"access_token":"fake-nous","refresh_token":"fake-refresh","tls":{"verify":false},"unrelated":"EXCLUDED"},"other":{"token":"EXCLUDED"}},"credential_pool":{"other":"EXCLUDED"},"unrelated":"EXCLUDED"}"#;
        let filtered = String::from_utf8(filter_auth(input).unwrap()).unwrap();
        assert!(filtered.contains("fake-nous"));
        assert!(!filtered.contains("EXCLUDED"));
        assert!(!filtered.contains("tls"));
        let cfg = filter_config(b"model:\n  provider: nous\n  default: example-free-model\n  api_key: EXCLUDED\nhooks: EXCLUDED\n").unwrap();
        let cfg = String::from_utf8(cfg).unwrap();
        assert!(cfg.contains("example-free-model"));
        assert!(!cfg.contains("EXCLUDED"));
    }
    #[test]
    fn guest_free_model_identity_is_preserved() {
        let input = br#"{"version":1,"providers":{"nous":{"auth_method":"anonymous","anon_token":"fake-guest","account_tier":"guest","welcome_claim":true},"other":{"token":"EXCLUDED"}}}"#;
        let filtered = String::from_utf8(filter_auth(input).unwrap()).unwrap();
        assert!(filtered.contains("fake-guest"));
        assert!(filtered.contains("welcome_claim"));
        assert!(!filtered.contains("EXCLUDED"));
    }
    #[test]
    fn unsupported_auth_is_rejected_without_secret_diagnostics() {
        for bytes in [
            b"PRIVATE_INVALID_JSON".as_slice(),
            br#"{"version":2,"providers":{"nous":{"access_token":"PRIVATE"}}}"#,
            br#"{"version":1,"providers":{"other":{"access_token":"PRIVATE"}}}"#,
        ] {
            assert!(!filter_auth(bytes)
                .unwrap_err()
                .to_string()
                .contains("PRIVATE"));
        }
        assert!(filter_config(b"model:\n  provider: other\n  default: example\n").is_err());
    }
}
