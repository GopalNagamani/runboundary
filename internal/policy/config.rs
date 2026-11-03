use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT: &str = include_str!("../../examples/agentvault.yaml");
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub sandbox: Sandbox,
    pub filesystem: Filesystem,
    pub environment: Environment,
    pub audit: Audit,
    #[serde(
        default,
        skip_serializing_if = "super::toolchains::Toolchains::is_empty"
    )]
    pub toolchains: super::toolchains::Toolchains,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Sandbox {
    pub enabled: bool,
    pub backend: String,
    pub fail_closed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_roots: Vec<PathBuf>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    pub protected: Vec<String>,
    pub allowed: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub inherit_all: bool,
    pub allow: Vec<String>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    pub enabled: bool,
    pub redact_secrets: bool,
}
impl Config {
    pub fn load(root: &Path) -> Result<Self> {
        let dir = crate::security::paths::Dir::open(root)?;
        let bytes = dir.read_file("agentvault.yaml", 128 * 1024)?.0;
        let config: Self = serde_yaml::from_slice(&bytes).context("invalid agentvault.yaml")?;
        super::validator::validate(&config)?;
        Ok(config)
    }
    pub fn for_host() -> Self {
        let mut config = Self::defaults();
        if cfg!(target_os = "macos") {
            config.sandbox.backend = "seatbelt".into();
        }
        config
    }
    pub fn defaults() -> Self {
        serde_yaml::from_str(DEFAULT).expect("built-in policy")
    }
}
