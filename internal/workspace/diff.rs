use super::prepare::Snapshot;
use std::{collections::BTreeSet, path::PathBuf};
#[derive(Debug, Clone)]
pub struct Change {
    pub path: PathBuf,
    pub kind: &'static str,
}
pub fn changes(before: &Snapshot, after: &Snapshot) -> Vec<Change> {
    let paths: BTreeSet<_> = before.keys().chain(after.keys()).collect();
    paths
        .into_iter()
        .filter_map(|p| {
            let kind = match (before.get(p), after.get(p)) {
                (None, Some(_)) => "added",
                (Some(_), None) => "deleted",
                (Some(a), Some(b))
                    if a.hash != b.hash || a.mode != b.mode || a.link_target != b.link_target =>
                {
                    "modified"
                }
                _ => return None,
            };
            Some(Change {
                path: p.clone(),
                kind,
            })
        })
        .collect()
}
