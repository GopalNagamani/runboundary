use super::config::Config;
use anyhow::{bail, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::{Component, Path};
pub struct Matcher {
    protected: GlobSet,
    allowed: GlobSet,
    mandatory: GlobSet,
    custom: GlobSet,
}
fn compile(patterns: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        if p.starts_with('/') || p.split('/').any(|x| x == "..") {
            bail!("patterns must be relative, without parent traversal");
        }
        b.add(Glob::new(p)?);
    }
    Ok(b.build()?)
}
impl Matcher {
    pub fn new(c: &Config) -> Result<Self> {
        // Exceptions are deliberately restricted; a wildcard allow cannot defeat a secret rule.
        for p in &c.filesystem.allowed {
            if !["**/.env.example", "**/.env.sample"].contains(&p.as_str()) {
                bail!("only the two built-in template exceptions are supported");
            }
        }
        Ok(Self {
            protected: compile(&c.filesystem.protected)?,
            allowed: compile(&c.filesystem.allowed)?,
            mandatory: compile(&Config::defaults().filesystem.protected)?,
            custom: compile(
                &c.filesystem
                    .protected
                    .iter()
                    .filter(|p| !Config::defaults().filesystem.protected.contains(p))
                    .cloned()
                    .collect::<Vec<_>>(),
            )?,
        })
    }
    pub fn protected(&self, p: &Path) -> bool {
        if p.components().any(|x| !matches!(x, Component::Normal(_))) {
            return true;
        }
        let components: Vec<_> = p.iter().collect();
        if components.iter().any(|x| {
            let s = x.to_string_lossy();
            matches!(
                s.as_ref(),
                ".git" | ".aws" | ".ssh" | ".kube" | ".codex" | ".claude" | "agentvault.yaml"
            ) || s.starts_with(".agentvault")
        }) {
            return true;
        }
        // Only default .env.* rule may be overridden by named templates.
        let template = matches!(
            p.file_name().and_then(|x| x.to_str()),
            Some(".env.example" | ".env.sample")
        );
        if template && self.allowed.is_match(p) {
            // A custom explicit protection wins, including *.example or exact paths.
            return self.custom.is_match(p);
        }
        self.mandatory.is_match(p) || self.protected.is_match(p)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_ancestors() {
        let m = Matcher::new(&Config::defaults()).unwrap();
        for p in [
            ".env",
            "a/.env.production",
            "a/key.pem",
            ".ssh/id_rsa",
            ".aws",
            ".git/config",
            "../a",
            ".env.example/x.key",
        ] {
            assert!(m.protected(Path::new(p)), "{p}");
        }
        assert!(!m.protected(Path::new("a/.env.example")));
        assert!(!m.protected(Path::new("src/main.rs")));
    }
    #[test]
    fn broad_allow_rejected() {
        let mut c = Config::defaults();
        c.filesystem.allowed.push("**".into());
        assert!(Matcher::new(&c).is_err());
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;
    #[test]
    fn custom_explicit_template_protection_wins() {
        let mut c = Config::defaults();
        c.filesystem.protected.push("**/.env.example".into());
        let m = Matcher::new(&c).unwrap();
        assert!(m.protected(Path::new("nested/.env.example")));
    }
    #[test]
    fn mandatory_protections_cannot_be_removed() {
        let mut c = Config::defaults();
        c.filesystem.protected.clear();
        let m = Matcher::new(&c).unwrap();
        assert!(m.protected(Path::new(".env")));
        assert!(m.protected(Path::new("nested/server.key")));
    }
}
