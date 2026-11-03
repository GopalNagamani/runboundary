//! Opt-in read-only SDK visibility, independent of host shell initialization.
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchains {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rust: Option<Rust>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub go: Option<Go>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub java: Option<Java>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub android: Option<Android>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ios: Option<Ios>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rust {
    pub toolchain_root: PathBuf,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Go {
    pub root: PathBuf,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Java {
    pub home: PathBuf,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Android {
    pub sdk_root: PathBuf,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ios {
    pub xcode_app: PathBuf,
}
#[derive(Default)]
pub struct Bindings {
    pub roots: Vec<PathBuf>,
    pub bins: Vec<PathBuf>,
    pub environment: BTreeMap<String, String>,
    pub checks: Vec<(String, Vec<String>)>,
    pub xcode_license: bool,
}
impl Toolchains {
    pub fn is_empty(&self) -> bool {
        self.rust.is_none()
            && self.go.is_none()
            && self.java.is_none()
            && self.android.is_none()
            && self.ios.is_none()
    }
    pub fn paths(&self) -> Vec<&Path> {
        let mut paths = Vec::new();
        if let Some(t) = &self.rust {
            paths.push(t.toolchain_root.as_path());
        }
        if let Some(t) = &self.go {
            paths.push(t.root.as_path());
        }
        if let Some(t) = &self.java {
            paths.push(t.home.as_path());
        }
        if let Some(t) = &self.android {
            paths.push(t.sdk_root.as_path());
        }
        if let Some(t) = &self.ios {
            paths.push(t.xcode_app.as_path());
        }
        paths
    }
    pub fn validate_syntax(&self) -> Result<()> {
        for path in self.paths() {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            {
                bail!("toolchain paths must be absolute without traversal");
            }
        }
        if self.android.is_some() && self.java.is_none() {
            bail!("Android SDK approval also requires toolchains.java.home; host JDK discovery is not imported");
        }
        if self.ios.is_some() && !cfg!(target_os = "macos") {
            bail!("iOS/Xcode toolchains require macOS");
        }
        Ok(())
    }
    pub fn bindings(&self, project: &Path) -> Result<Bindings> {
        self.validate_syntax()?;
        let mut result = Bindings::default();
        if let Some(t) = &self.rust {
            let root = approve(project, &t.toolchain_root)?;
            executable(&root, "bin/rustc")?;
            executable(&root, "bin/cargo")?;
            executable(&root, "bin/rustdoc")?;
            result.bins.push(root.join("bin"));
            result
                .environment
                .insert("RUSTC".into(), text(&root.join("bin/rustc"))?);
            result
                .environment
                .insert("RUSTDOC".into(), text(&root.join("bin/rustdoc"))?);
            result.checks.push((
                "Rust compiler".into(),
                vec![text(&root.join("bin/rustc"))?, "--version".into()],
            ));
            result.roots.push(root);
        }
        if let Some(t) = &self.go {
            let root = approve(project, &t.root)?;
            executable(&root, "bin/go")?;
            result.bins.push(root.join("bin"));
            result.environment.insert("GOROOT".into(), text(&root)?);
            result.checks.push((
                "Go compiler".into(),
                vec![text(&root.join("bin/go"))?, "version".into()],
            ));
            result.roots.push(root);
        }
        if let Some(t) = &self.java {
            let root = approve(project, &t.home)?;
            executable(&root, "bin/java")?;
            executable(&root, "bin/javac")?;
            result.bins.push(root.join("bin"));
            result.environment.insert("JAVA_HOME".into(), text(&root)?);
            result.checks.push((
                "Java compiler".into(),
                vec![text(&root.join("bin/javac"))?, "-version".into()],
            ));
            result.roots.push(root);
        }
        if let Some(t) = &self.android {
            let root = approve(project, &t.sdk_root)?;
            for folder in ["platforms", "build-tools"] {
                let path = root
                    .join(folder)
                    .canonicalize()
                    .context("Android SDK needs preinstalled platforms and build-tools")?;
                if !path.starts_with(&root) || !path.is_dir() {
                    bail!("Android SDK directory leaves its approved root");
                }
            }
            result
                .environment
                .insert("ANDROID_HOME".into(), text(&root)?);
            result
                .environment
                .insert("ANDROID_SDK_ROOT".into(), text(&root)?);
            // Deliberately do not add adb/emulator or import ~/.android/adbkey.
            result.roots.push(root);
        }
        if let Some(t) = &self.ios {
            result.xcode_license = true;
            let root = approve(project, &t.xcode_app)?;
            if root.extension() != Some(std::ffi::OsStr::new("app")) {
                bail!("xcode_app must name an Xcode application bundle");
            }
            executable(&root, "Contents/Developer/usr/bin/xcodebuild")?;
            let developer = root.join("Contents/Developer");
            result
                .environment
                .insert("DEVELOPER_DIR".into(), text(&developer)?);
            result.bins.push(developer.join("usr/bin"));
            result
                .bins
                .push(developer.join("Toolchains/XcodeDefault.xctoolchain/usr/bin"));
            result.checks.push((
                "Xcode build tool".into(),
                vec![
                    text(&developer.join("usr/bin/xcodebuild"))?,
                    "-version".into(),
                ],
            ));
            result.checks.push((
                "Xcode license acceptance".into(),
                vec![
                    text(&developer.join("usr/bin/xcodebuild"))?,
                    "-license".into(),
                    "check".into(),
                ],
            ));
            result.roots.push(root);
        }
        Ok(result)
    }
}
fn text(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("toolchain paths must be UTF-8")?
        .into())
}
pub(crate) fn approve(project: &Path, path: &Path) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .context("approved toolchain root is missing")?;
    let project = project.canonicalize()?;
    let broad = [
        "/",
        "/usr",
        "/usr/local",
        "/opt",
        "/etc",
        "/private",
        "/var",
        "/tmp",
        "/home",
        "/Users",
        "/Applications",
        "/Library",
    ];
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|p| p.canonicalize().ok());
    if broad.iter().any(|p|path==Path::new(p)) || home.as_ref()==Some(&path) || !path.is_dir()
        || path.starts_with(&project) || project.starts_with(&path)
        || ["/dev","/proc","/sys","/run","/private/var/run","/workspace","/home/agent"].iter().any(|p| path.starts_with(p))
        || path.components().any(|c|matches!(c,Component::Normal(n) if [".ssh",".aws",".kube",".codex",".claude",".git",".cargo"].iter().any(|secret|n==std::ffi::OsStr::new(secret)))) {
        bail!("toolchain root is broad, sensitive, reserved, or overlaps the project");
    }
    crate::sandbox::seatbelt::trusted(&path, true)
        .context("toolchain root and ancestors must have trusted ownership and permissions")?;
    text(&path)?;
    Ok(path)
}
fn executable(root: &Path, relative: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let path = root
        .join(relative)
        .canonicalize()
        .with_context(|| format!("toolchain is missing {relative}"))?;
    let meta = std::fs::metadata(&path)?;
    if !path.starts_with(root) || !meta.is_file() || meta.mode() & 0o111 == 0 {
        bail!("toolchain executable leaves approved root or is not executable");
    }
    crate::sandbox::seatbelt::trusted(&path, true)?;
    Ok(())
}

/// Caches contain no imported host state, and live outside the synchronized source.
pub fn private_environment(env: &mut BTreeMap<String, String>) {
    let home = env["HOME"].clone();
    for (key, suffix) in [
        ("XDG_CACHE_HOME", ".cache"),
        ("CARGO_HOME", ".cargo"),
        ("CARGO_TARGET_DIR", "build/rust"),
        ("GOPATH", "go"),
        ("GOCACHE", ".cache/go-build"),
        ("GOMODCACHE", "go/pkg/mod"),
        ("GRADLE_USER_HOME", ".gradle"),
        ("ANDROID_USER_HOME", ".android"),
        ("ANDROID_AVD_HOME", ".android/avd"),
        ("PYTHONUSERBASE", ".local"),
        ("PYTHONPYCACHEPREFIX", ".cache/python"),
        ("PIP_CACHE_DIR", ".cache/pip"),
        ("npm_config_cache", ".cache/npm"),
    ] {
        env.insert(key.into(), format!("{home}/{suffix}"));
    }
    env.insert("PYTHONNOUSERSITE".into(), "1".into());
}
