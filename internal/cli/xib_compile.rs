use crate::{
    interface_builder::{self, Request, INPUT_LIMIT},
    policy::{config::Config, matcher::Matcher},
    security::{audit, paths::Dir},
    workspace::prepare,
};
use anyhow::{bail, Result};
use std::path::Path;

pub fn execute(
    root: &Path,
    session: &str,
    runtime: &Path,
    input: &Path,
    output: &Path,
    module: Option<String>,
    deployment_target: String,
) -> Result<i32> {
    interface_builder::validate_relative(input, "xib")?;
    interface_builder::validate_relative(output, "nib")?;
    let (record, _lock) = super::review::load(root, session)?;
    let config = Config::load(root)?;
    let matcher = Matcher::new(&config)?;
    if matcher.protected(input) || matcher.protected(output) {
        bail!("protected Interface Builder path");
    }
    let workspace = record.workspace.canonicalize()?;
    let directory = Dir::open(&workspace)?;
    prepare::snapshot(&directory, &matcher, true)?;
    let source = directory.read_file(input, INPUT_LIMIT)?.0;
    // Early no-follow validation of the existing output parent, before any RPC.
    let (parent, name) = directory.parent(output)?;
    match parent.metadata(&name) {
        Ok(_) => bail!("output already exists; choose a fresh NIB path"),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .and_then(|e| e.raw_os_error())
                == Some(libc::ENOENT) => {}
        Err(e) => return Err(e),
    }
    let request = Request {
        source,
        module,
        deployment_target,
    };
    request.validate()?;
    audit::log(root, "xib_compile_requested", "explicit runtime approval; isolated compiler; no imported authentication or synchronization approval")?;
    let compilation = interface_builder::compile(root, &config, runtime, &request)?;
    compilation.artifact.publish(&workspace, output, &matcher)?;
    prepare::snapshot(&directory, &matcher, true)?;
    println!(
        "{}",
        String::from_utf8_lossy(&compilation.diagnostics).escape_debug()
    );
    println!(
        "Compiled NIB retained at {:?}. Original project unchanged.",
        output
    );
    println!("Review: runb diff {session}");
    println!("Approve after review: runb apply {session}");
    audit::log(
        root,
        "xib_compile_completed",
        "validated NIB published only in retained session; no source synchronization",
    )?;
    Ok(0)
}
