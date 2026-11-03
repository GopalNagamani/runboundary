use crate::{
    ib_bridge::Broker,
    policy::{config::Config, matcher::Matcher},
    sandbox::{backend::Backend, process},
    security::{audit, paths::Dir},
    workspace::{diff, prepare},
};
use anyhow::{bail, Context, Result};
use std::path::Path;

pub fn execute(
    root: &Path,
    id: Option<&str>,
    xcode_workspace: &Path,
    scheme: &str,
    runtime: &Path,
    allow_compiler_simulator_services: bool,
) -> Result<i32> {
    if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        bail!("ios-build requires Apple silicon macOS");
    }
    crate::interface_builder::validate_relative(xcode_workspace, "xcworkspace")?;
    if scheme.is_empty()
        || scheme.len() > 128
        || scheme.starts_with('-')
        || scheme.chars().any(|c| c.is_control())
    {
        bail!("invalid Xcode scheme");
    }
    let runtime = crate::interface_builder::approve_runtime(runtime)?;
    let config = Config::load(root)?;
    let matcher = Matcher::new(&config)?;
    if matcher.protected(xcode_workspace) {
        bail!("protected Xcode workspace");
    }
    let backend = Backend::select(root, &config)?;
    if config.toolchains.ios.is_none() {
        bail!("configure an approved Xcode toolchain first");
    }
    let (mut scratch, record, _lock) = if let Some(id) = id {
        let (record, lock) = super::review::load(root, id)?;
        (None, Some(record), Some(lock))
    } else {
        (
            Some(prepare::prepare(&Dir::open(root)?, &matcher)?),
            None,
            None,
        )
    };
    let workspace = if let Some(record) = &record {
        record.workspace.canonicalize()?
    } else {
        scratch
            .as_ref()
            .context("missing build workspace")?
            .path()
            .canonicalize()?
    };
    let directory = Dir::open(&workspace)?;
    let before = prepare::snapshot(&directory, &matcher, true)?;
    let (parent, name) = directory.parent(xcode_workspace)?;
    parent
        .child(&name)
        .context("Xcode workspace must be a real directory inside the filtered copy")?;
    let executable = backend.resolve("xcodebuild")?;
    let env = backend.environment(&config, &[], &workspace)?;
    let result = (|| -> Result<i32> {
        backend.probe(root, &workspace, &env)?;
        let home = Path::new(&env["HOME"]);
        let services = if allow_compiler_simulator_services {
            audit::log(root, "ios_compiler_simulator_services_approved", "compiler-only CoreSimulatorService/simdiskimaged access; shared services have host account authority")?;
            println!("Compiler Simulator services enabled explicitly. Shared Apple services can create private build devices and use host account authority.");
            crate::interface_builder::SimulatorServices::Enabled
        } else {
            crate::interface_builder::SimulatorServices::Restricted
        };
        let broker = Broker::start(root, &config, &runtime, &workspace, home, services)?;
        let derived = home.join("build/DerivedData");
        Dir::open(home)?.ensure_parent(Path::new("build/DerivedData/entry"))?;
        let args = vec![
            "-workspace".into(),
            workspace
                .join(xcode_workspace)
                .to_str()
                .context("invalid workspace path")?
                .into(),
            "-scheme".into(),
            scheme.into(),
            "-configuration".into(),
            "Debug".into(),
            "-sdk".into(),
            "iphonesimulator".into(),
            "-destination".into(),
            "generic/platform=iOS Simulator".into(),
            "-derivedDataPath".into(),
            derived
                .to_str()
                .context("invalid derived data path")?
                .into(),
            "-jobs".into(),
            "2".into(),
            "CODE_SIGNING_ALLOWED=NO".into(),
            format!(
                "IBC_EXEC={}",
                broker.wrapper.to_str().context("invalid bridge path")?
            ),
            format!(
                "ASSETCATALOG_EXEC={}",
                broker
                    .asset_wrapper
                    .to_str()
                    .context("invalid asset bridge path")?
            ),
            "build".into(),
        ];
        audit::log(root,"ios_build_requested","unsigned Simulator build; typed Interface Builder and asset broker; no authentication or apply approval")?;
        let mut command =
            backend.preview_command(root, &workspace, &env, &executable, &args, false)?;
        println!("Starting unsigned Simulator build in the filtered copy. Interface Builder and asset catalogs use the constrained broker.");
        let status = process::interactive(&mut command)?;
        broker.finish()?;
        let code = process::exit_code(status);
        audit::log(root, "ios_build_exited", &format!("exit_code={code}"))?;
        Ok(code)
    })();
    let cleanup = backend.cleanup_private_dirs(&workspace, &env);
    let after = prepare::snapshot(&directory, &matcher, true);
    cleanup.context("build private-directory cleanup failed; nothing applied")?;
    let after = after.context("unsafe build output rejected; nothing applied")?;
    let changes = diff::changes(&before, &after);
    for change in &changes {
        println!("  {} {:?}", change.kind, change.path);
    }
    if !changes.is_empty() {
        let session = if let Some(id) = id {
            id.to_owned()
        } else {
            let work = scratch
                .take()
                .context("missing temporary build workspace")?;
            let path = work.path().to_owned();
            let baseline = work.baseline;
            let _retained = work.temp.keep();
            super::review::retain(root, path, baseline)?
        };
        println!("Build-script edits remain unapplied. Review: agentvault review {session} --diff");
    }
    println!("Original project source unchanged. Derived build artifacts and broker state were disposable.");
    result
}
