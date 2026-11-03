use anyhow::Result;
use std::path::Path;
pub fn execute(root: &Path) -> Result<()> {
    crate::security::audit::show(root)
}
