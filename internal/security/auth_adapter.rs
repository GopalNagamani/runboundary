//! Explicit file-backed adapter manifests. Never discover or mount login directories.
use super::paths::Dir;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Adapter {
    version: u32,
    agent: String,
    files: Vec<Mapping>,
    #[serde(default)]
    terminal: BTreeMap<String, String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Mapping {
    source: PathBuf,
    destination: PathBuf,
    #[serde(default)]
    kind: Kind,
}
#[derive(Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
enum Kind {
    #[default]
    Credential,
    Cache,
    Executable,
    HermesNousAuth,
    HermesNousConfig,
}
fn private_read(path: &Path, limit: u64, private: bool) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        bail!("adapter sources must be absolute paths");
    }
    let root = Dir::open(Path::new("/"))?;
    let (parent, name) = root.parent(path.strip_prefix("/")?)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!("adapter file must belong to the current user");
    }
    let (bytes, identity) = parent.read_file(Path::new(&name), limit)?;
    if identity.mode & (if private { 0o077 } else { 0o022 }) != 0
        || identity.ino != metadata.ino()
        || identity.dev != metadata.dev()
    {
        bail!("adapter credentials must be private; cache/executable files must not be writable by others; all must be stable and single-linked");
    }
    Ok(bytes)
}
impl Adapter {
    pub fn load(path: &Path, agent: &str) -> Result<Self> {
        let bytes = private_read(path, 64 * 1024, true)?;
        Self::from_manifest(&bytes, agent)
    }
    pub fn from_manifest(bytes: &[u8], agent: &str) -> Result<Self> {
        let adapter: Self = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid adapter manifest; contents withheld"))?;
        if adapter.version != 1
            || Path::new(agent).file_name() != Some(OsStr::new(&adapter.agent))
            || adapter.agent.is_empty()
            || Path::new(&adapter.agent).components().count() != 1
        {
            bail!("adapter version or agent executable does not match");
        }
        if adapter.files.is_empty() || adapter.files.len() > 32 {
            bail!("adapter must name 1 to 32 individual files");
        }
        for (key, value) in &adapter.terminal {
            if !["COLORTERM", "COLORFGBG"].contains(&key.as_str())
                || value.len() > 64
                || value.chars().any(char::is_control)
            {
                bail!(
                    "adapter terminal settings accept only bounded COLORTERM and COLORFGBG values"
                );
            }
        }
        let mut destinations = BTreeSet::new();
        for file in &adapter.files {
            if file.destination.as_os_str().is_empty()
                || file
                    .destination
                    .components()
                    .any(|c| !matches!(c, Component::Normal(_)))
                || !destinations.insert(file.destination.clone())
            {
                bail!("adapter destinations must be unique home-relative paths without traversal");
            }
            if matches!(file.kind, Kind::HermesNousAuth | Kind::HermesNousConfig)
                && (adapter.agent != "hermes"
                    || file.destination
                        != Path::new(if matches!(file.kind, Kind::HermesNousAuth) {
                            ".hermes/auth.json"
                        } else {
                            ".hermes/config.yaml"
                        }))
            {
                bail!(
                    "Hermes projections require the Hermes agent and standard private destinations"
                );
            }
            if !file.source.is_absolute() {
                bail!("adapter sources must be absolute paths");
            }
        }
        Ok(adapter)
    }
    pub fn approved_manifest(path: &Path, agent: &str) -> Result<Vec<u8>> {
        let adapter = Self::load(path, agent)?;
        adapter.validate_sources()?;
        Ok(serde_json::to_vec_pretty(&adapter)?)
    }
    fn validate_sources(&self) -> Result<()> {
        for file in &self.files {
            // Setup checks metadata only; credential contents are not read before approval.
            let root = Dir::open(Path::new("/"))?;
            let (parent, name) = root.parent(file.source.strip_prefix("/")?)?;
            let m = parent.metadata(&name)?;
            let owner = std::fs::symlink_metadata(&file.source)?;
            let mask = if matches!(file.kind, Kind::Credential | Kind::HermesNousAuth) {
                0o077
            } else {
                0o022
            };
            if !m.regular()
                || m.links != 1
                || m.mode & mask != 0
                || owner.uid() != unsafe { libc::geteuid() }
            {
                bail!(
                    "adapter source must be an owned regular file with safe permissions: {:?}",
                    file.source
                );
            }
        }
        Ok(())
    }
    pub fn approval_lines(&self) -> Vec<String> {
        self.files
            .iter()
            .map(|f| {
                format!(
                    "{:?} -> private HOME/{:?} ({})",
                    f.source,
                    f.destination,
                    match f.kind {
                        Kind::Credential => "login",
                        Kind::Cache => "cache",
                        Kind::Executable => "executable",
                        Kind::HermesNousAuth => "Nous Portal credentials only",
                        Kind::HermesNousConfig => "Nous provider/model only",
                    }
                )
            })
            .collect()
    }
    pub fn freebuff_manifest(home: &Path) -> Result<Vec<u8>> {
        let base = home.join(".config/manicode");
        let mut files = Vec::new();
        for (name, kind, required) in [
            ("credentials.json", Kind::Credential, true),
            ("device-key.json", Kind::Credential, true),
            ("freebuff", Kind::Executable, true),
            ("freebuff-metadata.json", Kind::Cache, false),
            ("rg", Kind::Executable, false),
            ("tree-sitter.wasm", Kind::Cache, false),
        ] {
            let source = base.join(name);
            match std::fs::symlink_metadata(&source) {
                Ok(_) => files.push(Mapping { source, destination: PathBuf::from(".config/manicode").join(name), kind }),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && !required => (),
                Err(_) => bail!("Freebuff login/cache file missing: {source:?}; install and log into Freebuff normally first"),
            }
        }
        let adapter = Self {
            version: 1,
            agent: "freebuff".into(),
            files,
            terminal: BTreeMap::from([
                ("COLORTERM".into(), "truecolor".into()),
                ("COLORFGBG".into(), "15;0".into()),
            ]),
        };
        adapter.validate_sources()?;
        Ok(serde_json::to_vec_pretty(&adapter)?)
    }
    pub fn hermes_manifest(home: &Path) -> Result<Vec<u8>> {
        let base = home.join(".hermes");
        let adapter = Self {
            version: 1,
            agent: "hermes".into(),
            terminal: BTreeMap::new(),
            files: vec![
                Mapping {
                    source: base.join("auth.json"),
                    destination: PathBuf::from(".hermes/auth.json"),
                    kind: Kind::HermesNousAuth,
                },
                Mapping {
                    source: base.join("config.yaml"),
                    destination: PathBuf::from(".hermes/config.yaml"),
                    kind: Kind::HermesNousConfig,
                },
            ],
        };
        adapter.validate_sources().context(
            "Hermes Nous Portal files unavailable; install Hermes and select Nous Portal first",
        )?;
        Ok(serde_json::to_vec_pretty(&adapter)?)
    }
    pub fn configure(&self, env: &mut BTreeMap<String, String>) {
        env.extend(self.terminal.clone());
    }
    pub fn import(&self, home: &Path) -> Result<()> {
        // Validate all sources before creating destinations. Source bytes remain
        // outside logs/errors and are never written back after agent execution.
        let mut total = 0usize;
        let mut inputs = Vec::new();
        for file in &self.files {
            let bytes = private_read(
                &file.source,
                if matches!(file.kind, Kind::Executable) {
                    128 * 1024 * 1024
                } else {
                    256 * 1024
                },
                matches!(file.kind, Kind::Credential | Kind::HermesNousAuth),
            )
            .context("adapter input refused; file contents withheld")?;
            total = total
                .checked_add(bytes.len())
                .context("adapter size overflow")?;
            if total > 160 * 1024 * 1024 {
                bail!("adapter exceeds total import limit");
            }
            let bytes = match file.kind {
                Kind::HermesNousAuth => super::hermes_auth::filter_auth(&bytes)?,
                Kind::HermesNousConfig => super::hermes_auth::filter_config(&bytes)?,
                _ => bytes,
            };
            inputs.push(bytes);
        }
        let home = Dir::open(home)?;
        for (file, bytes) in self.files.iter().zip(inputs) {
            home.ensure_parent(&file.destination)?;
            home.create(
                &file.destination,
                &bytes,
                if matches!(file.kind, Kind::Executable) {
                    0o700
                } else {
                    0o600
                },
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn write(path: &Path, bytes: &[u8], mode: u32) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[test]
    fn explicit_import_is_narrow_private_and_not_written_back() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let secret = root.join("login.json");
        let cache = root.join("runtime");
        write(&secret, b"synthetic-secret", 0o600);
        write(&cache, b"synthetic-runtime", 0o755);
        write(&root.join("unapproved"), b"excluded", 0o600);
        let profile = root.join("adapter.json");
        write(&profile, &serde_json::to_vec(&serde_json::json!({"version":1,"agent":"example-agent","terminal":{"COLORFGBG":"15;0"},"files":[{"source":secret,"destination":".config/example/login.json"},{"source":cache,"destination":".config/example/runtime","kind":"executable"}]})).unwrap(), 0o600);
        let adapter = Adapter::load(&profile, "/opt/example-agent").unwrap();
        let home = tempfile::tempdir().unwrap();
        adapter.import(home.path()).unwrap();
        let login = home.path().join(".config/example/login.json");
        assert_eq!(std::fs::read(&login).unwrap(), b"synthetic-secret");
        assert_eq!(std::fs::metadata(&login).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(home.path().join(".config/example/runtime"))
                .unwrap()
                .mode()
                & 0o777,
            0o700
        );
        assert!(!home.path().join("unapproved").exists());
        write(&login, b"refreshed-synthetic", 0o600);
        assert_eq!(std::fs::read(secret).unwrap(), b"synthetic-secret");
        assert!(Adapter::load(&profile, "other-agent").is_err());
    }
    #[test]
    fn unsafe_credentials_and_destinations_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = root.join("login");
        write(&source, b"DO_NOT_PRINT_THIS_SECRET", 0o644);
        assert!(private_read(&source, 256, true).is_err());
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&source, root.join("link")).unwrap();
        assert!(private_read(&root.join("link"), 256, true).is_err());
        std::fs::hard_link(&source, root.join("hard")).unwrap();
        assert!(private_read(&source, 256, true).is_err());
        let profile = root.join("adapter.json");
        for destination in ["../escape", "/tmp/escape", ""] {
            write(&profile, &serde_json::to_vec(&serde_json::json!({"version":1,"agent":"example","files":[{"source":source,"destination":destination}]})).unwrap(), 0o600);
            assert!(Adapter::load(&profile, "example").is_err());
        }
        write(&profile, b"DO_NOT_PRINT_THIS_SECRET", 0o600);
        assert!(!Adapter::load(&profile, "example")
            .err()
            .unwrap()
            .to_string()
            .contains("DO_NOT_PRINT"));
    }
    #[test]
    fn failed_batch_does_not_import_credentials() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = root.join("login");
        write(&source, b"synthetic", 0o600);
        let profile = root.join("adapter.json");
        write(&profile, &serde_json::to_vec(&serde_json::json!({"version":1,"agent":"example","files":[{"source":source,"destination":"login"},{"source":root.join("missing"),"destination":"second"}]})).unwrap(), 0o600);
        let adapter = Adapter::load(&profile, "example").unwrap();
        let home = tempfile::tempdir().unwrap();
        assert!(adapter.import(home.path()).is_err());
        assert!(!home.path().join("login").exists());
    }
}
