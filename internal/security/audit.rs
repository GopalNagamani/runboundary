use super::paths::Dir;
use anyhow::{bail, Result};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
pub fn log(root: &Path, event: &str, detail: &str) -> Result<()> {
    let d = Dir::open(root)?;
    match d.metadata(std::ffi::OsStr::new(".runboundary")) {
        Ok(m) if m.directory() && m.mode & 0o077 == 0 => {}
        Ok(_) => bail!("unsafe audit directory"),
        Err(e) => {
            if e.downcast_ref::<std::io::Error>()
                .and_then(|e| e.raw_os_error())
                != Some(libc::ENOENT)
            {
                return Err(e);
            }
            d.mkdir(std::ffi::OsStr::new(".runboundary"))?;
        }
    }
    // Pin the directory; opening via /dev/fd is avoided by an openat append below.
    let dir = d.child(std::ffi::OsStr::new(".runboundary"))?;
    dir.append_audit(&serde_json::to_vec(&serde_json::json!({"timestamp_unix":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"pid":std::process::id(),"event":event,"detail":detail}))?)
}
pub fn show(root: &Path) -> Result<()> {
    let dir = Dir::open(root)?;
    let (bytes, _) = dir.read_file(".runboundary/audit.jsonl", 16 * 1024 * 1024)?;
    // Parse then re-encode so audit data cannot inject terminal control sequences.
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let value: serde_json::Value = serde_json::from_slice(line)?;
        println!("{}", serde_json::to_string(&value)?);
    }
    Ok(())
}
// Imports intentionally kept local in paths for descriptor based append.
