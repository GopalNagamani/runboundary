//! IBC_EXEC argument adapter. Files are opened only inside the build sandbox.
use super::*;
use crate::interface_builder::{
    build::{Format, Kind, Options},
    Artifact, INPUT_LIMIT,
};
use crate::policy::matcher::Matcher;
use std::collections::BTreeMap;
use std::io::Write;

pub struct Invocation {
    pub job: Job,
    pub inputs: Vec<PathBuf>,
    pub companion_strings: BTreeMap<String, PathBuf>,
    pub destination: Option<PathBuf>,
    pub partial: Option<PathBuf>,
    pub dependencies: Option<PathBuf>,
    pub auxiliary: BTreeMap<String, PathBuf>,
}
pub(super) fn once<T>(slot: &mut Option<T>, value: T) -> Result<()> {
    if slot.replace(value).is_some() {
        bail!("duplicate Interface Builder option");
    }
    Ok(())
}
pub fn parse(args: &[String]) -> Result<Invocation> {
    if args.len() > 256 || args.iter().map(String::len).sum::<usize>() > 65536 {
        bail!("Interface Builder argument limit exceeded");
    }
    let mut options = Options::default();
    options.devices.clear();
    let mut version = 0usize;
    let mut format = Format::Human;
    let mut partial = None;
    let mut dependencies = None;
    let mut compile = None;
    let mut compilation_dir = None;
    let mut link = None;
    let mut inputs = vec![];
    let mut companion_strings = BTreeMap::new();
    let mut module = None;
    let mut deployment = None;
    let mut platform = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        i += 1;
        let value = |i: &mut usize| -> Result<String> {
            let v = args
                .get(*i)
                .context("missing Interface Builder option value")?
                .clone();
            *i += 1;
            Ok(v)
        };
        match arg.as_str() {
            "--version" => version += 1,
            "--output-format" => {
                format = match value(&mut i)?.as_str() {
                    "human-readable-text" => Format::Human,
                    "xml1" => Format::Xml,
                    _ => bail!("unsupported Interface Builder output format"),
                };
            }
            "--errors" | "--warnings" | "--notices" => {}
            "--print-diagnostic-categories" => options.categories = true,
            "--auto-activate-custom-fonts" => options.auto_fonts = true,
            "--reference-external-strings-file" => options.external_strings = true,
            "--companion-strings-file" => {
                let value = value(&mut i)?;
                let (locale, path) = value
                    .split_once(':')
                    .context("companion strings require LOCALE:PATH")?;
                build::validate_locale(locale)?;
                let path = PathBuf::from(path);
                if path.extension().and_then(|s| s.to_str()) != Some("strings") {
                    bail!("companion strings input must be a .strings file");
                }
                if companion_strings.insert(locale.to_owned(), path).is_some() {
                    bail!("duplicate companion strings locale");
                }
            }
            "--module" => once(&mut module, value(&mut i)?)?,
            "--minimum-deployment-target" => once(&mut deployment, value(&mut i)?)?,
            "--platform" => once(&mut platform, value(&mut i)?)?,
            "--target-device" => options.devices.push(value(&mut i)?),
            "--output-partial-info-plist" => once(&mut partial, PathBuf::from(value(&mut i)?))?,
            "--generate-dependency-info" => once(&mut dependencies, PathBuf::from(value(&mut i)?))?,
            "--compile" => once(&mut compile, PathBuf::from(value(&mut i)?))?,
            "--compilation-directory" => once(&mut compilation_dir, PathBuf::from(value(&mut i)?))?,
            "--link" => once(&mut link, PathBuf::from(value(&mut i)?))?,
            _ if arg.starts_with('-') => {
                bail!("unsupported Interface Builder option {arg:?}; no unmediated fallback")
            }
            _ => inputs.push(PathBuf::from(arg)),
        }
    }
    if version > 0 {
        if version != 1
            || args.len() > 3
            || !inputs.is_empty()
            || compile.is_some()
            || compilation_dir.is_some()
            || link.is_some()
            || module.is_some()
            || deployment.is_some()
            || platform.is_some()
            || partial.is_some()
            || dependencies.is_some()
            || !options.devices.is_empty()
            || options.auto_fonts
            || options.external_strings
            || options.categories
            || !companion_strings.is_empty()
        {
            bail!("version query must not include compilation options");
        }
        return Ok(Invocation {
            job: Job::Version { format },
            inputs,
            companion_strings,
            destination: None,
            partial: None,
            dependencies: None,
            auxiliary: BTreeMap::new(),
        });
    }
    if format != Format::Human || platform.as_ref().is_some_and(|p| p != "iphonesimulator") {
        bail!("bridge supports human-readable Simulator builds only");
    }
    options.module = module;
    if let Some(target) = deployment {
        options.deployment_target = target;
    }
    if options.devices.is_empty() {
        options.devices = Options::default().devices;
    }
    options.partial_info = partial.is_some();
    options.dependencies = dependencies.is_some();
    options.companion_locales = companion_strings.keys().cloned().collect();
    options.validate()?;
    let (job, destination) = if let Some(destination) = link {
        if compile.is_some()
            || compilation_dir.is_some()
            || inputs.is_empty()
            || !companion_strings.is_empty()
        {
            bail!("invalid storyboard link command");
        }
        let names = inputs
            .iter()
            .map(|p| storyboard_name(p))
            .collect::<Result<Vec<_>>>()?;
        if names.len() > 64
            || names
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != names.len()
        {
            bail!("storyboard link input-count/uniqueness limit exceeded");
        }
        for n in &names {
            build::storyboard_input(n)?;
        }
        (
            Job::Link {
                inputs: names,
                options,
            },
            destination,
        )
    } else {
        if inputs.len() != 1 || (compile.is_some() && compilation_dir.is_some()) {
            bail!("compile requires one source and one destination");
        }
        let input = name(&inputs[0])?;
        let (kind, extension) = match inputs[0].extension().and_then(|s| s.to_str()) {
            Some("xib") => (Kind::Xib, "nib"),
            Some("storyboard") => (Kind::Storyboard, "storyboardc"),
            _ => bail!("unsupported Interface Builder input type"),
        };
        let destination = if let Some(destination) = compile {
            destination
        } else if let Some(dir) = compilation_dir {
            if kind != Kind::Storyboard {
                bail!("compilation-directory requires a storyboard");
            }
            dir.join(Path::new(&input).with_extension(extension))
        } else {
            bail!("missing Interface Builder destination");
        };
        let output = name(&destination)?;
        build::basename(&output, extension)?;
        if !companion_strings.is_empty()
            && destination.parent().and_then(Path::file_name)
                != Some(std::ffi::OsStr::new("Base.lproj"))
        {
            bail!("companion strings compilation requires a Base.lproj destination");
        }
        (
            Job::Compile {
                kind,
                input,
                output,
                options,
            },
            destination,
        )
    };
    Ok(Invocation {
        job,
        inputs,
        companion_strings,
        destination: Some(destination),
        partial,
        dependencies,
        auxiliary: BTreeMap::new(),
    })
}
pub(super) fn name(path: &Path) -> Result<String> {
    Ok(path
        .file_name()
        .and_then(|n| n.to_str())
        .context("invalid Interface Builder resource name")?
        .into())
}
fn storyboard_name(path: &Path) -> Result<String> {
    let leaf = name(path)?;
    let input = if let Some(parent) = path
        .parent()
        .filter(|p| p.extension() == Some(std::ffi::OsStr::new("lproj")))
    {
        format!("{}/{leaf}", name(parent)?)
    } else {
        leaf
    };
    build::storyboard_input(&input)?;
    Ok(input)
}
fn absolute(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => out.push("/"),
            std::path::Component::CurDir => {}
            std::path::Component::Normal(n) => out.push(n),
            _ => bail!("Interface Builder paths may not contain parent traversal"),
        }
    }
    #[cfg(target_os = "macos")]
    for (alias, target) in [("/var", "/private/var"), ("/tmp", "/private/tmp")] {
        if let Ok(suffix) = out.strip_prefix(alias) {
            return Ok(if suffix.as_os_str().is_empty() {
                PathBuf::from(target)
            } else {
                Path::new(target).join(suffix)
            });
        }
    }
    Ok(out)
}
fn under(path: &Path, root: &Path) -> Result<PathBuf> {
    let relative = path
        .strip_prefix(root)
        .context("Interface Builder path is outside the current build roots")?
        .to_owned();
    crate::interface_builder::validate_relative_file(&relative)?;
    Ok(relative)
}

pub(super) fn open_root(path: &Path) -> Result<Dir> {
    let path = absolute(path)?;
    Dir::open_absolute(&path).with_context(|| format!("open Interface Builder root {path:?}"))
}
fn publish_group(root: &Dir, output: &Path, files: Files, matcher: &Matcher) -> Result<()> {
    crate::interface_builder::validate_relative_file(output)?;
    if matcher.protected(output) {
        bail!("protected compiler output");
    }
    for name in files.keys() {
        if !name.as_os_str().is_empty() {
            crate::interface_builder::validate_relative_file(name)?;
        }
        if matcher.protected(&output.join(name)) {
            bail!("protected compiler output");
        }
    }
    let flat = files.contains_key(Path::new(""));
    if flat && files.len() != 1 {
        bail!("conflicting artifact file/directory paths");
    }
    root.ensure_parent(output)?;
    let (parent, name) = root.parent(output)?;
    if flat {
        parent.create(Path::new(&name), &files[Path::new("")], 0o600)?;
    } else {
        // All writes use the original pinned build-root capability. Reopening
        // an absolute DerivedData path would follow a substituted ancestor.
        parent.mkdir(&name)?;
        let bundle = parent.child(&name)?;
        for (path, bytes) in files {
            bundle.ensure_parent(&path)?;
            bundle.create(&path, &bytes, 0o600)?;
        }
    }
    Ok(())
}

pub fn execute(bridge: &Path, args: &[String]) -> Result<i32> {
    execute_invocation(bridge, parse(args)?)
}
pub fn execute_assets(bridge: &Path, args: &[String]) -> Result<i32> {
    execute_invocation(bridge, super::assets::parse(args)?)
}
fn execute_invocation(bridge: &Path, invocation: Invocation) -> Result<i32> {
    let bridge = absolute(bridge)?;
    let mut settings: Settings = serde_json::from_slice(
        &open_root(&bridge)?
            .read_file("settings.json", 8192)
            .context("read Interface Builder bridge settings")?
            .0,
    )?;
    if settings.version != 1 {
        bail!("unsupported bridge version");
    }
    if !settings.workspace.is_absolute() || !settings.derived.is_absolute() {
        bail!("bridge build roots must be absolute");
    }
    settings.workspace = absolute(&settings.workspace)?;
    settings.derived = absolute(&settings.derived)?;
    let expected = bridge
        .parent()
        .context("missing private build home")?
        .join("build/DerivedData");
    if bridge.file_name() != Some(std::ffi::OsStr::new(".agentvault-ib"))
        || settings.derived != expected
    {
        bail!("bridge output root must belong to the current private build home: expected {expected:?}, configured {:?}",settings.derived);
    }
    let mut inputs = Files::new();
    let mut input_bytes = 0usize;
    let mut input_maps = vec![];
    for input in &invocation.inputs {
        let full = absolute(input)?;
        let base = if full.starts_with(&settings.workspace) {
            &settings.workspace
        } else {
            &settings.derived
        };
        let relative = under(&full, base)?;
        let root = open_root(base)?;
        let local_name = if matches!(invocation.job, Job::Link { .. }) {
            storyboard_name(input)?
        } else {
            name(input)?
        };
        if matches!(
            invocation.job,
            Job::Link { .. } | Job::AssetCatalog { .. } | Job::AssetTagCombinations { .. }
        ) {
            let (parent, leaf) = root.parent(&relative)?;
            let artifact = Artifact::read_named(&parent, &leaf)?;
            if !artifact.directory {
                bail!("storyboard and asset catalog inputs must be directories");
            }
            for (path, bytes) in artifact.files {
                if inputs.len() >= 4096 {
                    bail!("bridge input file-count limit exceeded");
                }
                input_bytes = input_bytes
                    .checked_add(bytes.len())
                    .context("bridge input overflow")?;
                if input_bytes > 64 * 1024 * 1024 {
                    bail!("bridge input payload limit exceeded");
                }
                inputs.insert(Path::new(&local_name).join(path), bytes);
            }
        } else {
            let bytes = root.read_file(&relative, INPUT_LIMIT)?.0;
            input_bytes = input_bytes
                .checked_add(bytes.len())
                .context("bridge input overflow")?;
            if input_bytes > 64 * 1024 * 1024 {
                bail!("bridge input payload limit exceeded");
            }
            inputs.insert(PathBuf::from(&local_name), bytes);
        }
        input_maps.push((format!("Inputs/{local_name}"), full));
    }
    let matcher = Matcher::new(&Config::for_host())?;
    for (locale, path) in &invocation.companion_strings {
        let full = absolute(path)?;
        let base = if full.starts_with(&settings.workspace) {
            &settings.workspace
        } else {
            &settings.derived
        };
        let relative = under(&full, base)?;
        if matcher.protected(&relative) {
            bail!("protected companion strings input");
        }
        let bytes = open_root(base)?.read_file(&relative, INPUT_LIMIT)?.0;
        input_bytes = input_bytes
            .checked_add(bytes.len())
            .context("bridge input overflow")?;
        if input_bytes > 64 * 1024 * 1024 {
            bail!("bridge input payload limit exceeded");
        }
        let staged = build::companion_input(locale);
        input_maps.push((format!("Inputs/{}", staged.display()), full));
        if inputs.insert(staged, bytes).is_some() {
            bail!("duplicate bridge input");
        }
    }
    invocation.job.validate(&inputs)?;
    let localized = !invocation.companion_strings.is_empty();
    let destination = invocation
        .destination
        .as_ref()
        .map(|p| absolute(p))
        .transpose()?;
    let output_parent = if let Some(path) = &destination {
        let parent = if matches!(invocation.job, Job::Link { .. } | Job::AssetCatalog { .. }) {
            path.as_path()
        } else {
            let parent = path.parent().context("missing artifact parent")?;
            if localized {
                // The compiler returns Base.lproj and sibling locale folders.
                parent.parent().context("missing localization parent")?
            } else {
                parent
            }
        };
        // Parent can equal DerivedData; artifacts themselves must be descendants.
        if parent != settings.derived {
            under(parent, &settings.derived)?;
        }
        Some(parent.to_owned())
    } else {
        None
    };
    let partial = invocation
        .partial
        .as_ref()
        .map(|p| absolute(p))
        .transpose()?;
    let dependencies = invocation
        .dependencies
        .as_ref()
        .map(|p| absolute(p))
        .transpose()?;
    for path in partial.iter().chain(dependencies.iter()) {
        under(path, &settings.derived)?;
    }
    let mut auxiliary = BTreeMap::new();
    for (key, path) in &invocation.auxiliary {
        let path = absolute(path)?;
        under(&path, &settings.derived)?;
        input_maps.push((format!("Aux/{key}"), path.clone()));
        auxiliary.insert(key.clone(), path);
    }
    if let Some(path) = &partial {
        input_maps.push(("Aux/partial.plist".into(), path.clone()));
    }
    if let Some(path) = &dependencies {
        input_maps.push(("Aux/dependencies".into(), path.clone()));
    }
    let allow_empty_artifacts =
        matches!(&invocation.job, Job::AssetCatalog { options, .. } if options.symbols());
    let (reply, mut files) = exchange(&bridge, invocation.job, &inputs)?;
    std::io::stdout().write_all(reply.stdout.as_bytes())?;
    std::io::stderr().write_all(reply.stderr.as_bytes())?;
    if !reply.ok {
        bail!(
            "{}",
            reply
                .error
                .as_deref()
                .unwrap_or("Interface Builder job rejected")
        );
    }
    if let Some(parent) = output_parent {
        let matcher = Matcher::new(&Config::for_host())?;
        let derived = open_root(&settings.derived)?;
        for (key, path) in auxiliary {
            let bytes = files
                .remove(&Path::new("Aux").join(key))
                .context("missing asset symbol output")?;
            let relative = under(&path, &settings.derived)?;
            derived.ensure_parent(&relative)?;
            derived.create(&relative, &bytes, 0o600)?;
        }
        // Side files are separated from artifact groups and never select a host path.
        for (key, path) in [("partial.plist", partial), ("dependencies", dependencies)] {
            if let Some(path) = path {
                let mut bytes = files
                    .remove(&Path::new("Aux").join(key))
                    .context("missing compiler side output")?;
                if key == "dependencies" {
                    bytes = remap_dependencies(&bytes, &reply.stage_root, &input_maps, &parent)?;
                }
                let relative = under(&path, &settings.derived)?;
                derived.ensure_parent(&relative)?;
                derived.create(&relative, &bytes, 0o600)?;
            }
        }
        let mut groups: BTreeMap<PathBuf, Files> = BTreeMap::new();
        for (path, bytes) in files {
            let relative = path
                .strip_prefix("Outputs")
                .context("unexpected compiler output channel")?;
            let mut parts = relative.components();
            let first = parts.next().context("empty compiler output")?;
            let leaf = PathBuf::from(first.as_os_str());
            crate::interface_builder::validate_relative_file(&leaf)?;
            let leaf = if leaf.extension() == Some(std::ffi::OsStr::new("lproj")) {
                // Group each artifact inside a locale, rather than creating or
                // replacing the locale directory (which Xcode may already own).
                let resource = parts.next().context("missing localized artifact name")?;
                leaf.join(resource.as_os_str())
            } else {
                leaf
            };
            let rest: PathBuf = parts.collect();
            groups.entry(leaf).or_default().insert(rest, bytes);
        }
        if groups.is_empty() && !allow_empty_artifacts {
            bail!("compiler returned no artifacts");
        }
        for (leaf, files) in groups {
            let output = under(&parent.join(leaf), &settings.derived)?;
            publish_group(&derived, &output, files, &matcher)?;
        }
    } else if !files.is_empty() {
        bail!("compiler query returned unexpected files");
    }
    Ok(0)
}

// ld64 dependency records are opcode + nonempty UTF-8 + NUL. Preserve SDK
// dependencies, remap isolated compiler paths back to this build's paths.
pub fn remap_dependencies(
    bytes: &[u8],
    stage: &str,
    inputs: &[(String, PathBuf)],
    output: &Path,
) -> Result<Vec<u8>> {
    let mut cursor = 0;
    let mut out = vec![];
    let mut records = 0;
    while cursor < bytes.len() {
        let op = bytes[cursor];
        cursor += 1;
        if (records == 0 && op != 0) || (records > 0 && ![0x10, 0x11, 0x40].contains(&op)) {
            bail!("unsupported dependency-info opcode");
        }
        let end = bytes[cursor..]
            .iter()
            .position(|b| *b == 0)
            .context("unterminated dependency-info record")?
            + cursor;
        let value = std::str::from_utf8(&bytes[cursor..end])?;
        if value.is_empty() {
            bail!("empty dependency-info record");
        }
        let mut mapped = None;
        if op != 0 {
            let relative = value
                .strip_prefix(stage)
                .and_then(|s| s.strip_prefix('/'))
                .unwrap_or(value);
            for (prefix, path) in inputs {
                if let Ok(suffix) = Path::new(relative).strip_prefix(prefix) {
                    mapped = Some(if suffix.as_os_str().is_empty() {
                        path.clone()
                    } else {
                        path.join(suffix)
                    });
                    break;
                }
            }
            if mapped.is_none() {
                if let Ok(suffix) = Path::new(relative).strip_prefix("Outputs") {
                    mapped = Some(output.join(suffix));
                }
            }
            if (relative.starts_with("Inputs/") || relative.starts_with("Aux/")) && mapped.is_none()
            {
                bail!("unmapped isolated compiler dependency");
            }
        }
        out.push(op);
        if let Some(path) = mapped {
            out.extend_from_slice(path.to_str().context("invalid dependency path")?.as_bytes());
        } else {
            out.extend_from_slice(value.as_bytes());
        }
        out.push(0);
        cursor = end + 1;
        records += 1;
    }
    if records == 0 {
        bail!("missing dependency-info version");
    }
    Ok(out)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    #[test]
    fn system_aliases_normalize_without_resolving_build_paths_or_parent_traversal() {
        for (input, expected) in [
            (
                "/var/folders/nonexistent-build/Input.xib",
                "/private/var/folders/nonexistent-build/Input.xib",
            ),
            (
                "/tmp/nonexistent-build/Output.nib",
                "/private/tmp/nonexistent-build/Output.nib",
            ),
            ("/private/var/folders/build", "/private/var/folders/build"),
            ("/variable/build", "/variable/build"),
        ] {
            assert_eq!(absolute(Path::new(input)).unwrap(), Path::new(expected));
        }
        assert!(absolute(Path::new("/var/../host-secret")).is_err());
    }
}
