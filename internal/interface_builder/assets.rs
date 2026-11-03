//! Bounded asset-catalog operations. Paths and executable selection stay in the host.
use super::{build, *};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub deployment_target: String,
    pub devices: Vec<String>,
    pub app_icon: Option<String>,
    pub accent_color: Option<String>,
    pub development_region: Option<String>,
    pub bundle_identifier: Option<String>,
    pub compress_pngs: bool,
    pub on_demand_resources: bool,
    pub partial_info: bool,
    pub dependencies: bool,
    pub swift_symbols: bool,
    pub objc_symbols: bool,
    pub symbol_index: bool,
    pub swift_extensions: Option<bool>,
}
impl Default for Options {
    fn default() -> Self {
        let common = build::Options::default();
        Self {
            deployment_target: common.deployment_target,
            devices: common.devices,
            app_icon: None,
            accent_color: None,
            development_region: None,
            bundle_identifier: None,
            compress_pngs: false,
            on_demand_resources: false,
            partial_info: false,
            dependencies: false,
            swift_symbols: false,
            objc_symbols: false,
            symbol_index: false,
            swift_extensions: None,
        }
    }
}
pub fn resource_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 128
        || name.starts_with('-')
        || [".", ".."].contains(&name)
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-. ".contains(&b))
    {
        bail!("unsupported asset resource name");
    }
    Ok(())
}
impl Options {
    pub fn symbols(&self) -> bool {
        self.swift_symbols || self.objc_symbols || self.symbol_index
    }
    pub fn validate(&self) -> Result<()> {
        build::Options {
            deployment_target: self.deployment_target.clone(),
            devices: self.devices.clone(),
            ..build::Options::default()
        }
        .validate()?;
        for name in self.app_icon.iter().chain(self.accent_color.iter()) {
            resource_name(name)?;
        }
        if let Some(region) = &self.development_region {
            build::validate_locale(region)?;
        }
        if let Some(bundle) = &self.bundle_identifier {
            if bundle.len() > 255
                || bundle.split('.').any(|part| {
                    part.is_empty()
                        || !part.as_bytes()[0].is_ascii_alphanumeric()
                        || !part
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                })
            {
                bail!("invalid asset bundle identifier");
            }
        }
        if self.swift_extensions.is_some() && !self.swift_symbols {
            bail!("Swift asset extensions require Swift symbol generation");
        }
        Ok(())
    }
    pub fn auxiliary_outputs(&self) -> Vec<&'static str> {
        [
            (self.swift_symbols, "asset-symbols.swift"),
            (self.objc_symbols, "asset-symbols.h"),
            (self.symbol_index, "asset-symbol-index.plist"),
        ]
        .into_iter()
        .filter_map(|(enabled, name)| enabled.then_some(name))
        .collect()
    }
    pub fn arguments(&self, catalogs: &[String], stage: &Path) -> Result<Vec<String>> {
        if !stage.is_absolute() {
            bail!("asset compiler staging root must be absolute");
        }
        let path = |relative: &str| -> Result<String> {
            super::validate_relative_file(Path::new(relative))?;
            Ok(stage
                .join(relative)
                .to_str()
                .context("invalid asset staging path")?
                .into())
        };
        // actool is an ibtoold persona. Call the approved fixed compiler directly;
        // do not delegate to the account's pooled tool daemon.
        // Use absolute host-generated staging paths, as Xcode does. Worker
        // output resolution must not depend on the coordinator's directory.
        let mut args: Vec<String> = [
            "--persona",
            "actool",
            "--errors",
            "--warnings",
            "--notices",
            "--output-format",
            "human-readable-text",
            "--platform",
            "iphonesimulator",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        args.extend([
            "--compile".into(),
            path("Outputs")?,
            "--minimum-deployment-target".into(),
            self.deployment_target.clone(),
        ]);
        for device in &self.devices {
            args.extend(["--target-device".into(), device.clone()]);
        }
        for (flag, value) in [
            ("--app-icon", &self.app_icon),
            ("--accent-color", &self.accent_color),
            ("--development-region", &self.development_region),
            ("--bundle-identifier", &self.bundle_identifier),
        ] {
            if let Some(value) = value {
                args.extend([flag.into(), value.clone()]);
            }
        }
        if self.compress_pngs {
            args.push("--compress-pngs".into());
        }
        args.extend([
            "--enable-on-demand-resources".into(),
            if self.on_demand_resources {
                "YES"
            } else {
                "NO"
            }
            .into(),
        ]);
        // actool checks app-icon metadata arguments even for symbol-only jobs.
        // Without this flag it can exit successfully without writing symbols.
        // The symbol operation itself still does not emit a partial plist.
        if self.partial_info || (self.symbols() && self.app_icon.is_some()) {
            args.extend([
                "--output-partial-info-plist".into(),
                path("Aux/partial.plist")?,
            ]);
        }
        for (enabled, flag, path) in [
            (
                self.swift_symbols,
                "--generate-swift-asset-symbols",
                "Aux/asset-symbols.swift",
            ),
            (
                self.objc_symbols,
                "--generate-objc-asset-symbols",
                "Aux/asset-symbols.h",
            ),
            (
                self.symbol_index,
                "--generate-asset-symbol-index",
                "Aux/asset-symbol-index.plist",
            ),
        ] {
            if enabled {
                args.extend([
                    flag.into(),
                    stage
                        .join(path)
                        .to_str()
                        .context("invalid asset side-output path")?
                        .into(),
                ]);
            }
        }
        if let Some(extensions) = self.swift_extensions {
            args.extend([
                "--generate-swift-asset-symbol-extensions".into(),
                if extensions { "YES" } else { "NO" }.into(),
            ]);
        }
        for name in catalogs {
            build::basename(name, "xcassets")?;
            args.push(path(&format!("Inputs/{name}"))?);
        }
        Ok(args)
    }
}

/// A read-only catalog query; input paths are fixed by the host after staging.
pub fn tag_arguments(catalogs: &[String], stage: &Path) -> Result<Vec<String>> {
    if !stage.is_absolute() {
        bail!("asset compiler staging root must be absolute");
    }
    let mut args = [
        "--persona",
        "actool",
        "--print-asset-tag-combinations",
        "--output-format",
        "xml1",
    ]
    .map(String::from)
    .to_vec();
    for catalog in catalogs {
        build::basename(catalog, "xcassets")?;
        args.push(
            stage
                .join("Inputs")
                .join(catalog)
                .to_str()
                .context("invalid asset staging path")?
                .into(),
        );
    }
    Ok(args)
}

pub fn validate(catalogs: &[String], files: &build::Files, options: &Options) -> Result<()> {
    options.validate()?;
    if catalogs.is_empty() || catalogs.len() > 16 {
        bail!("invalid asset catalog count");
    }
    let mut seen = std::collections::BTreeSet::new();
    for catalog in catalogs {
        build::basename(catalog, "xcassets")?;
        if !seen.insert(catalog.to_ascii_lowercase())
            || !files.contains_key(&Path::new(catalog).join("Contents.json"))
        {
            bail!("duplicate asset catalog or missing Contents.json");
        }
    }
    if files.keys().any(|p| {
        !catalogs
            .iter()
            .any(|c| p.starts_with(c) && p.components().count() > 1)
    }) {
        bail!("unexpected asset catalog input");
    }
    Ok(())
}
