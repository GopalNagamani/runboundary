use super::{bubblewrap, mounts, seatbelt};
use crate::{
    policy::config::Config,
    security::{environment, paths::Dir},
};
use anyhow::{bail, Result};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};
pub struct Backend {
    macos: bool,
    runtime_roots: Vec<PathBuf>,
    sdk: crate::policy::toolchains::Bindings,
}
impl Backend {
    pub fn select(root: &Path, config: &Config) -> Result<Self> {
        if unsafe { libc::geteuid() } == 0 {
            bail!("run RunBoundary as an unprivileged user, not root");
        }
        let sdk = config.toolchains.bindings(root)?;
        match (std::env::consts::OS,config.sandbox.backend.as_str()) {
            ("linux","bubblewrap")=>{crate::platform::linux::require()?;Ok(Self {macos:false,runtime_roots:vec![],sdk})},
            ("macos","seatbelt")=>Ok(Self {macos:true,runtime_roots:seatbelt::validate_runtime_roots(root,&config.sandbox.runtime_roots)?,sdk}),
            _=>bail!("configured backend does not match this host: use bubblewrap on Linux or seatbelt on macOS; no fallback is allowed"),
        }
    }
    pub fn name(&self) -> &'static str {
        if self.macos {
            "seatbelt"
        } else {
            "bubblewrap"
        }
    }
    fn read_roots(&self) -> Vec<PathBuf> {
        let mut roots = self.runtime_roots.clone();
        roots.extend(self.sdk.roots.iter().cloned());
        roots
    }
    pub fn tool_checks(&self) -> &[(String, Vec<String>)] {
        &self.sdk.checks
    }
    pub fn tool_roots(&self) -> &[PathBuf] {
        &self.sdk.roots
    }
    pub fn resolve(&self, name: &str) -> Result<PathBuf> {
        let requested = Path::new(name);
        if !requested.is_absolute() && requested.components().count() != 1 {
            bail!("executable must be a basename or absolute path");
        }
        let candidates = if requested.is_absolute() {
            vec![requested.to_owned()]
        } else {
            self.sdk.bins.iter().map(|bin| bin.join(name)).collect()
        };
        for candidate in candidates {
            let Ok(path) = candidate.canonicalize() else {
                continue;
            };
            if self.sdk.roots.iter().any(|root| path.starts_with(root)) {
                use std::os::unix::fs::MetadataExt;
                let meta = std::fs::metadata(&path)?;
                if !meta.is_file() || meta.mode() & 0o111 == 0 {
                    continue;
                }
                seatbelt::trusted(&path, true)?;
                return Ok(path);
            }
        }
        if self.macos {
            seatbelt::resolve(name, &self.read_roots())
        } else {
            mounts::resolve(name)
        }
    }
    pub fn environment(
        &self,
        config: &Config,
        auth: &[String],
        work: &Path,
    ) -> Result<BTreeMap<String, String>> {
        let mut env = environment::build(config, auth)?;
        {
            let parent = work
                .parent()
                .ok_or_else(|| anyhow::anyhow!("workspace has no private parent"))?;
            let dir = Dir::open(parent)?;
            for name in ["sandbox-home", "sandbox-tmp"] {
                dir.mkdir(std::ffi::OsStr::new(name))?;
            }
            for (key, name) in [("HOME", "sandbox-home"), ("TMPDIR", "sandbox-tmp")] {
                let value = parent.join(name).canonicalize()?;
                env.insert(
                    key.into(),
                    (if self.macos {
                        value
                    } else if key == "HOME" {
                        PathBuf::from("/home/agent")
                    } else {
                        PathBuf::from("/tmp")
                    })
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("non-UTF-8 sandbox path"))?
                    .into(),
                );
            }
        }
        if self.macos {
            // CoreFoundation prefers the account database home over HOME.
            // Pin its override too; never inherit a host-provided value.
            env.insert("CFFIXED_USER_HOME".into(), env["HOME"].clone());
            let mut paths = vec![
                PathBuf::from("/usr/bin"),
                PathBuf::from("/bin"),
                PathBuf::from("/usr/sbin"),
                PathBuf::from("/sbin"),
            ];
            // Approved runtime bins precede Apple shims (e.g. xcrun's python3 shim).
            for root in self.runtime_roots.iter().rev() {
                paths.insert(0, root.join("bin"));
            }
            env.insert(
                "PATH".into(),
                std::env::join_paths(paths)?
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("invalid runtime PATH"))?,
            );
            // Rust clients may otherwise query a Keychain service that is not
            // available inside this sandbox. Use the already-readable public
            // OS PEM bundle, keeping certificate/hostname verification enabled.
            let public_ca = seatbelt::public_ca_bundle()?;
            env.insert("SSL_CERT_FILE".into(), public_ca.into());
            env.insert("CODEX_CA_CERTIFICATE".into(), public_ca.into());
        }
        let mut paths = self.sdk.bins.clone();
        paths.extend(std::env::split_paths(&env["PATH"]));
        env.insert(
            "PATH".into(),
            std::env::join_paths(paths)?
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid toolchain PATH"))?,
        );
        env.extend(self.sdk.environment.clone());
        crate::policy::toolchains::private_environment(&mut env);
        let home = Dir::open(
            &work
                .parent()
                .ok_or_else(|| anyhow::anyhow!("missing session parent"))?
                .join("sandbox-home"),
        )?;
        for path in [
            ".cache/python/entry",
            ".cache/pip/entry",
            ".cache/npm/entry",
            ".cargo/entry",
            ".gradle/entry",
            ".android/avd/entry",
            ".local/entry",
            "go/pkg/mod/entry",
            "build/rust/entry",
        ] {
            home.ensure_parent(Path::new(path))?;
        }
        Ok(env)
    }
    /// Remove disposable login/cache directories before retaining edits.
    pub fn cleanup_private_dirs(&self, work: &Path, env: &BTreeMap<String, String>) -> Result<()> {
        {
            let parent = work
                .parent()
                .ok_or_else(|| anyhow::anyhow!("missing private parent"))?
                .canonicalize()?;
            for (key, name) in [("HOME", "sandbox-home"), ("TMPDIR", "sandbox-tmp")] {
                let path = if !self.macos {
                    parent.join(name)
                } else {
                    PathBuf::from(
                        env.get(key)
                            .ok_or_else(|| anyhow::anyhow!("missing private directory"))?,
                    )
                };
                if path != parent.join(name) {
                    bail!("refusing cleanup outside the private session parent");
                }
                match std::fs::symlink_metadata(&path) {
                    Ok(meta) if meta.file_type().is_symlink() => std::fs::remove_file(&path)?,
                    Ok(_) => std::fs::remove_dir_all(&path)?,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(())
    }
    pub fn probe(&self, root: &Path, work: &Path, env: &BTreeMap<String, String>) -> Result<()> {
        if self.macos {
            seatbelt::probe_with_access(
                root,
                work,
                env,
                seatbelt::Access {
                    runtimes: &self.runtime_roots,
                    sdks: &self.sdk.roots,
                    xcode_license: self.sdk.xcode_license,
                    network: seatbelt::Network::Agent,
                },
            )
        } else {
            bubblewrap::probe_with_roots(
                root,
                work,
                env,
                Some(
                    &work
                        .parent()
                        .ok_or_else(|| anyhow::anyhow!("missing session parent"))?
                        .join("sandbox-home"),
                ),
                &self.sdk.roots,
            )
        }
    }
    /// Preview keeps filesystem/process controls; TCP listening needs explicit approval.
    pub fn preview_command(
        &self,
        root: &Path,
        work: &Path,
        env: &BTreeMap<String, String>,
        exe: &Path,
        args: &[String],
        allow_network_listen: bool,
    ) -> Result<Command> {
        if self.macos {
            seatbelt::command_with_access(
                root,
                work,
                env,
                exe,
                args,
                seatbelt::Access {
                    runtimes: &self.runtime_roots,
                    sdks: &self.sdk.roots,
                    xcode_license: self.sdk.xcode_license,
                    network: seatbelt::Network::Agent,
                },
                Some(allow_network_listen),
            )
        } else {
            self.command(root, work, env, exe, args)
        }
    }
    /// The isolated fixed compiler receives a profile built without the normal
    /// agent's IP/resolver socket grants. This never changes agent/preview policy.
    pub(crate) fn offline_compiler_command(
        &self,
        root: &Path,
        work: &Path,
        env: &BTreeMap<String, String>,
        exe: &Path,
        args: &[String],
    ) -> Result<Command> {
        if !self.macos {
            bail!("offline Interface Builder compilation requires Seatbelt");
        }
        seatbelt::command_with_access(
            root,
            work,
            env,
            exe,
            args,
            seatbelt::Access {
                runtimes: &self.runtime_roots,
                sdks: &self.sdk.roots,
                xcode_license: self.sdk.xcode_license,
                network: seatbelt::Network::OfflineCompiler,
            },
            None,
        )
    }
    pub fn command(
        &self,
        root: &Path,
        work: &Path,
        env: &BTreeMap<String, String>,
        exe: &Path,
        args: &[String],
    ) -> Result<Command> {
        if self.macos {
            seatbelt::command_with_access(
                root,
                work,
                env,
                exe,
                args,
                seatbelt::Access {
                    runtimes: &self.runtime_roots,
                    sdks: &self.sdk.roots,
                    xcode_license: self.sdk.xcode_license,
                    network: seatbelt::Network::Agent,
                },
                None,
            )
        } else {
            bubblewrap::command_with_roots(
                root,
                work,
                env,
                exe,
                args,
                Some(
                    &work
                        .parent()
                        .ok_or_else(|| anyhow::anyhow!("missing session parent"))?
                        .join("sandbox-home"),
                ),
                &self.sdk.roots,
            )
        }
    }
}
