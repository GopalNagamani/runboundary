//! Typed operations for the Xcode bridge. Input bytes, never caller host paths.
use super::*;
use serde::{Deserialize, Serialize};
pub type Files = BTreeMap<PathBuf, Vec<u8>>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Xib,
    Storyboard,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Human,
    Xml,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub module: Option<String>,
    pub deployment_target: String,
    pub devices: Vec<String>,
    pub auto_fonts: bool,
    pub external_strings: bool,
    pub categories: bool,
    pub partial_info: bool,
    pub dependencies: bool,
    /// Locale identifiers only. The host chooses each staged strings path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub companion_locales: Vec<String>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            module: None,
            deployment_target: "17.2".into(),
            devices: vec!["iphone".into(), "ipad".into()],
            auto_fonts: false,
            external_strings: false,
            categories: false,
            partial_info: false,
            dependencies: false,
            companion_locales: vec![],
        }
    }
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        Request {
            source: b"options-validation".to_vec(),
            module: self.module.clone(),
            deployment_target: self.deployment_target.clone(),
        }
        .validate()?;
        if self.companion_locales.len() > 64 {
            bail!("companion strings locale-count limit exceeded");
        }
        let mut locales = std::collections::BTreeSet::new();
        for locale in &self.companion_locales {
            validate_locale(locale)?;
            if !locales.insert(locale.to_ascii_lowercase()) {
                bail!("duplicate companion strings locale");
            }
        }
        if self.devices.is_empty()
            || self.devices.len() > 2
            || self
                .devices
                .iter()
                .any(|d| !["iphone", "ipad"].contains(&d.as_str()))
            || (self.devices.len() == 2 && self.devices[0] == self.devices[1])
        {
            bail!("unsupported target-device list");
        }
        Ok(())
    }
    fn args(&self) -> Vec<String> {
        let mut args = vec![
            "--errors".into(),
            "--warnings".into(),
            "--notices".into(),
            "--minimum-deployment-target".into(),
            self.deployment_target.clone(),
        ];
        for d in &self.devices {
            args.extend(["--target-device".into(), d.clone()]);
        }
        if let Some(module) = &self.module {
            args.extend(["--module".into(), module.clone()]);
        }
        for (flag, enabled) in [
            ("--auto-activate-custom-fonts", self.auto_fonts),
            ("--reference-external-strings-file", self.external_strings),
            ("--print-diagnostic-categories", self.categories),
        ] {
            if enabled {
                args.push(flag.into());
            }
        }
        if self.partial_info {
            args.extend([
                "--output-partial-info-plist".into(),
                "Aux/partial.plist".into(),
            ]);
        }
        args.extend(["--output-format".into(), "human-readable-text".into()]);
        args
    }
}

pub fn validate_locale(locale: &str) -> Result<()> {
    if locale.is_empty()
        || locale.len() > 64
        || !locale.as_bytes()[0].is_ascii_alphabetic()
        || locale.eq_ignore_ascii_case("Base")
        || locale
            .split(['-', '_'])
            .any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        bail!("unsupported companion strings locale");
    }
    Ok(())
}

pub fn companion_input(locale: &str) -> PathBuf {
    Path::new("Strings").join(format!("{locale}.strings"))
}

const LOCALIZATION_DIR: &str = "RunBoundaryLocalization";
const LOCALIZATION_MANIFEST: &str = "RunBoundaryLocalization/locales.json";
const APPLE_STRINGS_MANIFEST: &str = "StringsFiles.plist";

/// Link inputs retain their optional locale, never an arbitrary caller path.
pub fn storyboard_input(name: &str) -> Result<()> {
    let path = Path::new(name);
    validate_relative_file(path)?;
    match path.components().count() {
        1 => basename(name, "storyboardc"),
        2 => {
            let locale = path.parent().and_then(Path::to_str).unwrap();
            let locale = locale
                .strip_suffix(".lproj")
                .context("expected a locale directory")?;
            if locale != "Base" {
                validate_locale(locale)?;
            }
            basename(
                path.file_name().and_then(OsStr::to_str).unwrap(),
                "storyboardc",
            )
        }
        _ => bail!("expected a storyboard basename with an optional locale directory"),
    }
}

fn localization_file(storyboard: &Path, locale: &str) -> PathBuf {
    storyboard
        .join(LOCALIZATION_DIR)
        .join(locale)
        .join(storyboard.file_name().unwrap())
        .with_extension("strings")
}

fn localization_locales(storyboard: &Path, files: &Files) -> Result<Vec<String>> {
    if files.contains_key(&storyboard.join(APPLE_STRINGS_MANIFEST)) {
        bail!(
            "raw storyboard strings paths cannot cross compiler jobs; rebuild through the bridge"
        );
    }
    let locales = if let Some(bytes) = files.get(&storyboard.join(LOCALIZATION_MANIFEST)) {
        if bytes.len() > 8192 {
            bail!("storyboard localization metadata limit exceeded");
        }
        let locales: Vec<String> = serde_json::from_slice(bytes)?;
        if locales.is_empty() {
            bail!("empty storyboard localization metadata");
        }
        Options {
            companion_locales: locales.clone(),
            ..Options::default()
        }
        .validate()?;
        for locale in &locales {
            let bytes = files
                .get(&localization_file(storyboard, locale))
                .context("missing packaged storyboard strings")?;
            if bytes.len() as u64 > INPUT_LIMIT {
                bail!("packaged storyboard strings exceed 8 MiB");
            }
        }
        locales
    } else {
        vec![]
    };
    let prefix = storyboard.join(LOCALIZATION_DIR);
    if files.keys().any(|path| {
        path.starts_with(&prefix)
            && path != &storyboard.join(LOCALIZATION_MANIFEST)
            && !locales
                .iter()
                .any(|locale| path == &localization_file(storyboard, locale))
    }) {
        bail!("unexpected packaged storyboard localization file");
    }
    Ok(locales)
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Reconstruct Apple's path manifest from validated packaged bytes. The linker
/// never sees a prior staging path or a caller-supplied path from a plist.
fn link_staging_files(names: &[String], files: &Files) -> Result<Files> {
    let mut staged = files.clone();
    for (index, name) in names.iter().enumerate() {
        let storyboard = Path::new(name);
        let locales = localization_locales(storyboard, files)?;
        if locales.is_empty() {
            continue;
        }
        staged.remove(&storyboard.join(LOCALIZATION_MANIFEST));
        let mut plist =
            String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict>");
        for locale in locales {
            let packaged = localization_file(storyboard, &locale);
            let destination = Path::new("Strings")
                .join(index.to_string())
                .join(&locale)
                .join(packaged.file_name().unwrap());
            let bytes = staged
                .remove(&packaged)
                .context("missing packaged storyboard strings")?;
            plist.push_str(&format!(
                "<key>{}</key><string>Inputs/{}</string>",
                xml_escape(&locale),
                xml_escape(
                    destination
                        .to_str()
                        .context("invalid staged strings path")?
                )
            ));
            if staged.insert(destination, bytes).is_some() {
                bail!("duplicate staged storyboard strings");
            }
        }
        plist.push_str("</dict></plist>");
        staged.insert(storyboard.join(APPLE_STRINGS_MANIFEST), plist.into_bytes());
    }
    validate_files(&staged)?;
    Ok(staged)
}

fn package_storyboard_localization(
    output: &str,
    options: &Options,
    inputs: &Files,
    files: &mut Files,
) -> Result<()> {
    let storyboard = Path::new("Outputs/Base.lproj").join(output);
    if files
        .keys()
        .any(|p| p.starts_with(storyboard.join(LOCALIZATION_DIR)))
    {
        bail!("compiler output conflicts with bridge localization metadata");
    }
    if files
        .remove(&storyboard.join(APPLE_STRINGS_MANIFEST))
        .is_none()
    {
        bail!(
            "compiler omitted storyboard strings metadata; outputs: {:?}",
            files.keys().take(16).collect::<Vec<_>>()
        );
    }
    files.insert(
        storyboard.join(LOCALIZATION_MANIFEST),
        serde_json::to_vec(&options.companion_locales)?,
    );
    for locale in &options.companion_locales {
        files.insert(
            localization_file(&storyboard, locale),
            inputs[&companion_input(locale)].clone(),
        );
    }
    validate_files(files).context("localized storyboard artifact budget")
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Job {
    Version {
        format: Format,
    },
    AssetVersion {
        format: Format,
    },
    AssetTagCombinations {
        catalogs: Vec<String>,
    },
    AssetCatalog {
        catalogs: Vec<String>,
        options: super::assets::Options,
    },
    Compile {
        kind: Kind,
        input: String,
        output: String,
        options: Options,
    },
    Link {
        inputs: Vec<String>,
        options: Options,
    },
}
pub fn basename(name: &str, extension: &str) -> Result<()> {
    let p = Path::new(name);
    validate_relative(p, extension)?;
    if p.components().count() != 1 || name.len() > 240 || name.chars().any(char::is_control) {
        bail!("expected a bounded resource basename");
    }
    Ok(())
}
fn validate_files(files: &Files) -> Result<()> {
    let total: usize = files.values().map(Vec::len).sum();
    if total > OUTPUT_LIMIT || files.len() > FILE_COUNT_LIMIT {
        bail!("bridge input budget exceeded");
    }
    let matcher = crate::policy::matcher::Matcher::new(&Config::for_host())?;
    let mut nodes = std::collections::BTreeSet::new();
    for path in files.keys() {
        validate_relative_file(path)?;
        for parent in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
            nodes.insert(parent.to_owned());
        }
        if nodes.len() > FILE_COUNT_LIMIT {
            bail!("bridge input entry-count limit exceeded");
        }
        if matcher.protected(path) {
            bail!("protected bridge input");
        }
    }
    Ok(())
}
impl Job {
    pub fn validate(&self, files: &Files) -> Result<()> {
        validate_files(files)?;
        match self {
            Self::Version { .. } | Self::AssetVersion { .. } => {
                if !files.is_empty() {
                    bail!("version queries cannot include files");
                }
            }
            Self::AssetCatalog { catalogs, options } => {
                super::assets::validate(catalogs, files, options)?
            }
            Self::AssetTagCombinations { catalogs } => {
                super::assets::validate(catalogs, files, &super::assets::Options::default())?
            }
            Self::Compile {
                kind,
                input,
                output,
                options,
            } => {
                options.validate()?;
                basename(
                    input,
                    if *kind == Kind::Xib {
                        "xib"
                    } else {
                        "storyboard"
                    },
                )?;
                basename(
                    output,
                    if *kind == Kind::Xib {
                        "nib"
                    } else {
                        "storyboardc"
                    },
                )?;
                if files.len() != 1 + options.companion_locales.len() {
                    bail!("compile accepts one source and its declared companion strings files");
                }
                let source = files
                    .get(Path::new(input))
                    .context("missing compile source")?;
                Request {
                    source: source.clone(),
                    module: options.module.clone(),
                    deployment_target: options.deployment_target.clone(),
                }
                .validate()?;
                for locale in &options.companion_locales {
                    let bytes = files
                        .get(&companion_input(locale))
                        .context("missing companion strings input")?;
                    if bytes.len() as u64 > INPUT_LIMIT {
                        bail!("companion strings input exceeds 8 MiB");
                    }
                }
            }
            Self::Link { inputs, options } => {
                options.validate()?;
                if !options.companion_locales.is_empty() {
                    bail!("companion strings are supported only for compilation");
                }
                if inputs.is_empty() || inputs.len() > 64 || files.is_empty() {
                    bail!("invalid storyboard link inputs");
                }
                let mut seen = std::collections::BTreeSet::new();
                for name in inputs {
                    storyboard_input(name)?;
                    if !seen.insert(name.to_ascii_lowercase())
                        || !files.keys().any(|p| {
                            p.starts_with(name)
                                && p.components().count() > Path::new(name).components().count()
                        })
                    {
                        bail!("missing/duplicate storyboard input");
                    }
                    localization_locales(Path::new(name), files)?;
                }
                if files.keys().any(|p| {
                    !inputs.iter().any(|n| {
                        p.starts_with(n)
                            && p.components().count() > Path::new(n).components().count()
                    })
                }) {
                    bail!("unexpected storyboard input file");
                }
            }
        }
        Ok(())
    }
}

pub struct Output {
    pub files: Files,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stage_root: String,
}
fn declared_dependencies(
    work: &Path,
    inputs: &Files,
    outputs: &Files,
    partial: bool,
) -> Result<Vec<u8>> {
    // This is the bridge's declared I/O graph, not an export of all SDK files
    // read internally by ibtool. ios-build uses fresh DerivedData on every run.
    let mut data = b"\0runboundary-ib-bridge-v1\0".to_vec();
    let paths = inputs
        .keys()
        .map(|p| (0x10, work.join("Inputs").join(p)))
        .chain(outputs.keys().map(|p| (0x40, work.join(p))))
        .chain(partial.then(|| (0x40, work.join("Aux/partial.plist"))));
    for (op, path) in paths {
        let text = path.to_str().context("non-UTF-8 dependency path")?;
        if text.is_empty() || text.contains('\0') {
            bail!("invalid dependency record");
        }
        data.push(op);
        data.extend_from_slice(text.as_bytes());
        data.push(0);
        if data.len() > 1024 * 1024 {
            bail!("dependency-info budget exceeded");
        }
    }
    Ok(data)
}
pub fn execute(
    project: &Path,
    config: &Config,
    runtime: &Path,
    job: &Job,
    inputs: &Files,
    cancel: &AtomicBool,
) -> Result<Output> {
    execute_with_services(
        project,
        config,
        runtime,
        job,
        inputs,
        cancel,
        SimulatorServices::Restricted,
    )
}

fn asset_output_context(staged: &Dir, expected: &Path, result: &Capture) -> String {
    let entries = |name: &str| {
        staged
            .child(OsStr::new(name))
            .and_then(|dir| dir.entries())
            .map(|paths| paths.into_iter().take(16).collect::<Vec<_>>())
    };
    let diagnostics: String = String::from_utf8_lossy(&result.diagnostics)
        .chars()
        .take(4096)
        .flat_map(char::escape_debug)
        .collect();
    format!("collect asset compiler output {expected:?}; Outputs entries: {:?}; Aux entries: {:?}; compiler diagnostics: {diagnostics}", entries("Outputs"), entries("Aux"))
}

fn asset_output_file(staged: &Dir, path: &Path, result: &Capture) -> Result<Vec<u8>> {
    staged
        .read_file(path, 1024 * 1024)
        .map(|(bytes, _)| bytes)
        .with_context(|| asset_output_context(staged, path, result))
}

pub fn execute_with_services(
    project: &Path,
    config: &Config,
    runtime: &Path,
    job: &Job,
    inputs: &Files,
    cancel: &AtomicBool,
    services: SimulatorServices,
) -> Result<Output> {
    job.validate(inputs)?;
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        bail!("Interface Builder bridge requires Apple silicon macOS");
    }
    if cancel.load(Ordering::Relaxed) {
        bail!("Interface Builder build cancelled");
    }
    let ios = config
        .toolchains
        .ios
        .as_ref()
        .context("configure Xcode before using the bridge")?;
    let mut cfg = Config::for_host();
    cfg.toolchains.ios = Some(crate::policy::toolchains::Ios {
        xcode_app: ios.xcode_app.clone(),
    });
    let runtime = approve_runtime(runtime)
        .with_context(|| format!("approve compiler runtime {runtime:?}"))?;
    let backend = Backend::select(project, &cfg).context("select approved compiler toolchain")?;
    let compiler = backend
        .resolve("ibtoold")
        .context("resolve approved ibtoold compiler")?;
    let temp = tempfile::Builder::new()
        .prefix("runboundary-ib-job-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .context("create private compiler job directory")?;
    let parent = Dir::open(temp.path())?;
    parent.mkdir(OsStr::new("workspace"))?;
    let work = temp.path().join("workspace").canonicalize()?;
    let staged = Dir::open(&work)?;
    for dir in ["Inputs", "Outputs", "Aux"] {
        staged.mkdir(OsStr::new(dir))?;
    }
    if matches!(job, Job::Compile { options, .. } if !options.companion_locales.is_empty()) {
        staged
            .child(OsStr::new("Outputs"))?
            .mkdir(OsStr::new("Base.lproj"))?;
    }
    let input_dir = staged.child(OsStr::new("Inputs"))?;
    let staged_inputs = match job {
        Job::Link { inputs: names, .. } => link_staging_files(names, inputs)?,
        _ => inputs.clone(),
    };
    for (name, bytes) in &staged_inputs {
        input_dir.ensure_parent(name)?;
        input_dir.create(name, bytes, 0o600)?;
    }
    let mut env = backend
        .environment(&cfg, &[], &work)
        .context("create compiler environment")?;
    backend.probe(project, &work, &env)?;
    let catalog = Path::new(&env["HOME"]).join("Library/Developer/CoreSimulator/Profiles/Runtimes");
    std::fs::create_dir_all(&catalog).context("create private compiler runtime catalog")?;
    std::os::unix::fs::symlink(
        &runtime,
        catalog.join(runtime.file_name().context("runtime name missing")?),
    )
    .context("register approved runtime in private compiler catalog")?;
    env.insert("IBToolNeverDeque".into(), "1".into());
    let args = match job {
        Job::Version { format } => vec![
            "--version".into(),
            "--output-format".into(),
            match format {
                Format::Human => "human-readable-text",
                Format::Xml => "xml1",
            }
            .into(),
        ],
        Job::AssetVersion { format } => vec![
            "--persona".into(),
            "actool".into(),
            "--version".into(),
            "--output-format".into(),
            match format {
                Format::Human => "human-readable-text",
                Format::Xml => "xml1",
            }
            .into(),
        ],
        Job::AssetCatalog { catalogs, options } => options.arguments(catalogs, &work)?,
        Job::AssetTagCombinations { catalogs } => super::assets::tag_arguments(catalogs, &work)?,
        Job::Compile {
            input,
            output,
            options,
            ..
        } => {
            let mut args = options.args();
            // Xcode 26.5 defaults to LNEPhase0. Later local encoders cover
            // more UIKit properties without requesting a Simulator device.
            // Keep normal preflight/fallback behavior; never use LNEForce,
            // which bypasses unsupported-property checks. This is a fixed
            // host choice, not a caller-selectable compiler option.
            args.extend(["--compilation-mode-for-ios".into(), "LNEPhase2".into()]);
            for locale in &options.companion_locales {
                args.extend([
                    "--companion-strings-file".into(),
                    format!("{locale}:Inputs/{}", companion_input(locale).display()),
                ]);
            }
            let output = if options.companion_locales.is_empty() {
                format!("Outputs/{output}")
            } else {
                format!("Outputs/Base.lproj/{output}")
            };
            args.extend(["--compile".into(), output, format!("Inputs/{input}")]);
            args
        }
        Job::Link { inputs, options } => {
            let mut args = options.args();
            args.extend(["--link".into(), "Outputs".into()]);
            args.extend(inputs.iter().map(|name| format!("Inputs/{name}")));
            args
        }
    };
    let base = backend.offline_compiler_command(project, &work, &env, &compiler, &args)?;
    let mut command = compiler_access_with_services(&base, &runtime, services)?;
    let result = capture_cancellable(&mut command, Duration::from_secs(60), Some(cancel))
        .with_context(|| format!("run isolated compiler {compiler:?}"))?;
    if !result.success {
        let diagnostics = String::from_utf8_lossy(&result.diagnostics);
        let hint = if services == SimulatorServices::Restricted
            && diagnostics.contains("Failed to find or create execution context")
            && diagnostics.contains("CoreSimulatorService")
        {
            "\nThis resource requires a Simulator execution context. To explicitly permit shared Apple services for the isolated compiler, rerun ios-build with --allow-compiler-simulator-services. Those services have host account authority; the default mode keeps them blocked."
        } else {
            ""
        };
        bail!(
            "isolated Interface Builder job failed:\n{}{hint}",
            diagnostics
                .lines()
                .map(|line| line.escape_debug().to_string())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    let mut files = Files::new();
    if let Job::AssetCatalog { options, .. } = job {
        if !options.symbols() {
            let artifact = Artifact::read_named(&staged, OsStr::new("Outputs"))
                .with_context(|| asset_output_context(&staged, Path::new("Outputs"), &result))?;
            for (name, bytes) in artifact.files {
                files.insert(Path::new("Outputs").join(name), bytes);
            }
        }
        for name in options.auxiliary_outputs() {
            files.insert(
                Path::new("Aux").join(name),
                asset_output_file(&staged, &Path::new("Aux").join(name), &result)?,
            );
        }
        if options.partial_info {
            // actool's symbol-only operation does not compile icons or produce
            // partial metadata. The later catalog compile supplies those keys.
            let bytes = if options.symbols() {
                b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict/></plist>"
                    .to_vec()
            } else {
                asset_output_file(&staged, Path::new("Aux/partial.plist"), &result)?
            };
            files.insert(PathBuf::from("Aux/partial.plist"), bytes);
        }
        if options.dependencies {
            let records = declared_dependencies(&work, inputs, &files, false)?;
            files.insert(PathBuf::from("Aux/dependencies"), records);
        }
    } else if !matches!(
        job,
        Job::Version { .. } | Job::AssetVersion { .. } | Job::AssetTagCombinations { .. }
    ) {
        let artifact = Artifact::read_named(&staged, OsStr::new("Outputs"))?;
        for (name, bytes) in artifact.files {
            files.insert(Path::new("Outputs").join(name), bytes);
        }
        if let Job::Compile {
            kind: Kind::Storyboard,
            output,
            options,
            ..
        } = job
        {
            if !options.companion_locales.is_empty() {
                package_storyboard_localization(output, options, inputs, &mut files)?;
            }
        }
        let options = match job {
            Job::Compile { options, .. } | Job::Link { options, .. } => options,
            _ => unreachable!(),
        };
        if options.dependencies {
            let bytes = declared_dependencies(&work, inputs, &files, options.partial_info)?;
            staged.create(Path::new("Aux/dependencies"), &bytes, 0o600)?;
        }
        for (flag, name) in [
            (options.partial_info, "partial.plist"),
            (options.dependencies, "dependencies"),
        ] {
            if flag {
                files.insert(
                    Path::new("Aux").join(name),
                    staged
                        .read_file(Path::new("Aux").join(name), 1024 * 1024)?
                        .0,
                );
            }
        }
    }
    Ok(Output {
        files,
        stdout: result.stdout,
        stderr: result.stderr,
        stage_root: work
            .to_str()
            .context("invalid compiler staging path")?
            .into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_asset_output_identifies_the_file_and_preserves_bounded_compiler_diagnostics() {
        let temp = tempfile::tempdir().unwrap();
        let staged = Dir::open(temp.path()).unwrap();
        staged.mkdir(OsStr::new("Outputs")).unwrap();
        staged.mkdir(OsStr::new("Aux")).unwrap();
        staged
            .create(Path::new("Outputs/Assets.car"), b"artifact", 0o600)
            .unwrap();
        staged
            .create(Path::new("Aux/renamed.h"), b"header", 0o600)
            .unwrap();
        let result = Capture {
            success: true,
            stdout: vec![],
            stderr: vec![],
            diagnostics: [
                b"actool compilation-results\n".as_slice(),
                &vec![b'x'; 10000],
            ]
            .concat(),
        };
        let error =
            asset_output_file(&staged, Path::new("Aux/asset-symbols.h"), &result).unwrap_err();
        let message = format!("{error:#}");
        for expected in [
            "Aux/asset-symbols.h",
            "Assets.car",
            "renamed.h",
            "actool compilation-results",
            "No such file or directory",
        ] {
            assert!(message.contains(expected), "{message}");
        }
        assert!(message.len() < 6000);
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::ENOENT)
        );
    }

    #[test]
    fn storyboard_localization_survives_disposable_jobs_without_preserving_compiler_paths() {
        let name = "Base.lproj/Launch&Screen.storyboardc";
        let options = Options {
            companion_locales: vec!["zh-Hans".into()],
            ..Options::default()
        };
        let source = Files::from([(
            companion_input("zh-Hans"),
            b"\"label.text\" = \"Translated\";".to_vec(),
        )]);
        let mut outputs = Files::from([
            (
                PathBuf::from(format!("Outputs/{name}/Info.plist")),
                b"storyboard".to_vec(),
            ),
            (
                PathBuf::from(format!("Outputs/{name}/StringsFiles.plist")),
                b"old /deleted/compiler/path".to_vec(),
            ),
        ]);
        package_storyboard_localization(
            "Launch&Screen.storyboardc",
            &options,
            &source,
            &mut outputs,
        )
        .unwrap();
        let inputs: Files = outputs
            .into_iter()
            .map(|(p, b)| (p.strip_prefix("Outputs").unwrap().to_owned(), b))
            .collect();
        let job = Job::Link {
            inputs: vec![name.into()],
            options: Options::default(),
        };
        job.validate(&inputs).unwrap();
        let staged = link_staging_files(&[name.into()], &inputs).unwrap();
        assert!(!staged
            .keys()
            .any(|p| p.starts_with(Path::new(name).join(LOCALIZATION_DIR))));
        assert_eq!(
            staged[Path::new("Strings/0/zh-Hans/Launch&Screen.strings")],
            source[&companion_input("zh-Hans")]
        );
        let plist =
            std::str::from_utf8(&staged[&Path::new(name).join(APPLE_STRINGS_MANIFEST)]).unwrap();
        assert!(plist.contains(
            "<key>zh-Hans</key><string>Inputs/Strings/0/zh-Hans/Launch&amp;Screen.strings</string>"
        ));
        assert!(!plist.contains("/deleted/compiler/path"));
        assert_eq!(xml_escape("<&>\"'"), "&lt;&amp;&gt;&quot;&apos;");
        #[cfg(target_os = "macos")]
        {
            // Apple's parser must read the regenerated manifest, including a
            // resource name requiring XML escaping. No compiler/service needed.
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), plist).unwrap();
            let parsed = Command::new("/usr/bin/plutil")
                .args(["-convert", "json", "-o", "-"])
                .arg(file.path())
                .output()
                .unwrap();
            assert!(
                parsed.status.success(),
                "{}",
                String::from_utf8_lossy(&parsed.stderr)
            );
            let dictionary: BTreeMap<String, String> =
                serde_json::from_slice(&parsed.stdout).unwrap();
            assert_eq!(
                dictionary,
                BTreeMap::from([(
                    "zh-Hans".into(),
                    "Inputs/Strings/0/zh-Hans/Launch&Screen.strings".into()
                )])
            );
        }
    }

    #[test]
    fn link_rejects_raw_paths_and_forged_or_incomplete_localization_packages() {
        let name = "Base.lproj/Main.storyboardc";
        let job = Job::Link {
            inputs: vec![name.into()],
            options: Options::default(),
        };
        let minimal = Files::from([(Path::new(name).join("Info.plist"), b"storyboard".to_vec())]);
        job.validate(&minimal).unwrap();
        assert!(job
            .validate(&Files::from([(
                PathBuf::from(name),
                b"flat file is not a storyboard directory".to_vec()
            )]))
            .is_err());
        let mut raw = minimal.clone();
        raw.insert(
            Path::new(name).join(APPLE_STRINGS_MANIFEST),
            b"caller file paths".to_vec(),
        );
        assert!(job.validate(&raw).is_err());
        for metadata in [
            b"[]".as_slice(),
            b"[\"../escape\"]",
            b"[\"en\",\"EN\"]",
            b"[\"Base\"]",
            b"[\"en\"]",
            b"{\"en\":\"/host/file\"}",
        ] {
            let mut files = minimal.clone();
            files.insert(
                Path::new(name).join(LOCALIZATION_MANIFEST),
                metadata.to_vec(),
            );
            assert!(job.validate(&files).is_err());
        }
        let mut files = minimal;
        files.insert(
            Path::new(name).join(LOCALIZATION_MANIFEST),
            b"[\"en\"]".to_vec(),
        );
        files.insert(
            localization_file(Path::new(name), "en"),
            b"translation".to_vec(),
        );
        job.validate(&files).unwrap();
        files.insert(
            Path::new(name).join("RunBoundaryLocalization/extra"),
            vec![],
        );
        assert!(job.validate(&files).is_err());
        for invalid in [
            "../Main.storyboardc",
            "/host/Main.storyboardc",
            "dir/Main.storyboardc",
            "Base.lproj/../Main.storyboardc",
            "base.lproj/Main.storyboardc",
        ] {
            assert!(storyboard_input(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn declared_dependencies_round_trip_without_forwarding_an_unsupported_compiler_flag() {
        let options = Options {
            dependencies: true,
            ..Options::default()
        };
        assert!(!options
            .args()
            .iter()
            .any(|arg| arg == "--generate-dependency-info"));
        let inputs = Files::from([(PathBuf::from("View.xib"), b"source".to_vec())]);
        let outputs = Files::from([(PathBuf::from("Outputs/View.nib"), b"artifact".to_vec())]);
        let records = declared_dependencies(Path::new("/stage"), &inputs, &outputs, true).unwrap();
        let mappings = vec![
            ("Inputs/View.xib".into(), PathBuf::from("/copy/View.xib")),
            (
                "Aux/partial.plist".into(),
                PathBuf::from("/build/View.plist"),
            ),
        ];
        let remapped = crate::ib_bridge::client::remap_dependencies(
            &records,
            "/stage",
            &mappings,
            Path::new("/build/App.app"),
        )
        .unwrap();
        assert_eq!(remapped,b"\0runboundary-ib-bridge-v1\0\x10/copy/View.xib\0\x40/build/App.app/View.nib\0\x40/build/View.plist\0");
    }
}
