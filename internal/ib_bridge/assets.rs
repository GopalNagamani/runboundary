//! Parse the finite actool build interface; caller paths stay in the sandbox.
use super::{
    client::{name, once, Invocation},
    *,
};
use crate::interface_builder::{assets::Options, build::Format};
use std::collections::BTreeMap;

pub fn parse(args: &[String]) -> Result<Invocation> {
    if args.len() > 256 || args.iter().map(String::len).sum::<usize>() > 65536 {
        bail!("asset compiler argument limit exceeded");
    }
    if args.iter().any(|s| s == "--version") {
        let format = match args
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
        {
            ["--version"] | ["--version", "--output-format", "human-readable-text"] => {
                Format::Human
            }
            ["--version", "--output-format", "xml1"] => Format::Xml,
            _ => bail!("asset version query must not include compilation options"),
        };
        return Ok(Invocation {
            job: Job::AssetVersion { format },
            inputs: vec![],
            companion_strings: BTreeMap::new(),
            destination: None,
            partial: None,
            dependencies: None,
            auxiliary: BTreeMap::new(),
        });
    }
    if args.iter().any(|s| s == "--print-asset-tag-combinations") {
        return parse_tag_query(args);
    }
    let mut options = Options::default();
    options.devices.clear();
    let mut inputs = vec![];
    let mut destination = None;
    let mut partial = None;
    let mut dependencies = None;
    let mut auxiliary = BTreeMap::new();
    let mut platform = None;
    let mut deployment = None;
    let mut format = None;
    let mut on_demand = None;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        index += 1;
        let value = |index: &mut usize| -> Result<String> {
            let value = args
                .get(*index)
                .context("missing asset compiler option value")?
                .clone();
            *index += 1;
            Ok(value)
        };
        let boolean = |index: &mut usize| -> Result<bool> {
            match value(index)?.as_str() {
                "YES" => Ok(true),
                "NO" => Ok(false),
                _ => bail!("asset compiler boolean must be YES or NO"),
            }
        };
        match arg.as_str() {
            "--errors" | "--warnings" | "--notices" => {}
            "--compile" => once(&mut destination, PathBuf::from(value(&mut index)?))?,
            "--output-format" => once(&mut format, value(&mut index)?)?,
            "--platform" => once(&mut platform, value(&mut index)?)?,
            "--target-device" => options.devices.push(value(&mut index)?),
            "--minimum-deployment-target" => once(&mut deployment, value(&mut index)?)?,
            "--app-icon" => once(&mut options.app_icon, value(&mut index)?)?,
            "--accent-color" => once(&mut options.accent_color, value(&mut index)?)?,
            "--development-region" => once(&mut options.development_region, value(&mut index)?)?,
            "--bundle-identifier" => once(&mut options.bundle_identifier, value(&mut index)?)?,
            "--compress-pngs" => options.compress_pngs = true,
            "--enable-on-demand-resources" => once(&mut on_demand, boolean(&mut index)?)?,
            "--output-partial-info-plist" => once(&mut partial, PathBuf::from(value(&mut index)?))?,
            "--export-dependency-info" => {
                once(&mut dependencies, PathBuf::from(value(&mut index)?))?
            }
            "--generate-swift-asset-symbol-extensions" => {
                once(&mut options.swift_extensions, boolean(&mut index)?)?
            }
            "--generate-swift-asset-symbols"
            | "--generate-objc-asset-symbols"
            | "--generate-asset-symbol-index" => {
                let (key, enabled) = match arg.as_str() {
                    "--generate-swift-asset-symbols" => {
                        ("asset-symbols.swift", &mut options.swift_symbols)
                    }
                    "--generate-objc-asset-symbols" => {
                        ("asset-symbols.h", &mut options.objc_symbols)
                    }
                    _ => ("asset-symbol-index.plist", &mut options.symbol_index),
                };
                if auxiliary
                    .insert(key.into(), PathBuf::from(value(&mut index)?))
                    .is_some()
                {
                    bail!("duplicate asset symbol output");
                }
                *enabled = true;
            }
            _ if arg.starts_with('-') => {
                bail!("unsupported asset compiler option {arg:?}; no unmediated fallback")
            }
            _ => inputs.push(PathBuf::from(arg)),
        }
    }
    if format
        .as_deref()
        .is_some_and(|f| f != "human-readable-text")
        || platform.as_deref().is_some_and(|p| p != "iphonesimulator")
    {
        bail!("asset bridge supports human-readable Simulator builds only");
    }
    options.partial_info = partial.is_some();
    options.dependencies = dependencies.is_some();
    options.on_demand_resources = on_demand.unwrap_or(false);
    if let Some(target) = deployment {
        options.deployment_target = target;
    }
    if options.devices.is_empty() {
        options.devices = Options::default().devices;
    }
    options.validate()?;
    let catalogs = catalog_names(&inputs)?;
    Ok(Invocation {
        job: Job::AssetCatalog { catalogs, options },
        inputs,
        companion_strings: BTreeMap::new(),
        destination: Some(destination.context("asset compilation requires an output directory")?),
        partial,
        dependencies,
        auxiliary,
    })
}

fn catalog_names(inputs: &[PathBuf]) -> Result<Vec<String>> {
    let catalogs = inputs.iter().map(|p| name(p)).collect::<Result<Vec<_>>>()?;
    if catalogs.is_empty() || catalogs.len() > 16 {
        bail!("invalid asset catalog count");
    }
    let mut names = std::collections::BTreeSet::new();
    for catalog in &catalogs {
        build::basename(catalog, "xcassets")?;
        if !names.insert(catalog.to_ascii_lowercase()) {
            bail!("duplicate asset catalog basename");
        }
    }
    Ok(catalogs)
}

fn parse_tag_query(args: &[String]) -> Result<Invocation> {
    let mut query = None;
    let mut format = None;
    let mut inputs = vec![];
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--print-asset-tag-combinations" => once(&mut query, ())?,
            "--output-format" => once(
                &mut format,
                args.next().context("missing asset query format")?.as_str(),
            )?,
            _ if arg.starts_with('-') => bail!("unsupported asset tag query option {arg:?}"),
            _ => inputs.push(PathBuf::from(arg)),
        }
    }
    if format.is_some_and(|f| f != "xml1") {
        bail!("asset tag queries support XML output only");
    }
    let catalogs = catalog_names(&inputs)?;
    Ok(Invocation {
        job: Job::AssetTagCombinations { catalogs },
        inputs,
        companion_strings: BTreeMap::new(),
        destination: None,
        partial: None,
        dependencies: None,
        auxiliary: BTreeMap::new(),
    })
}
