//! Bounded OpenStep parser with insertion-only project edits. No project code runs.
use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
};

#[derive(Debug)]
struct Node {
    value: Value,
    end: usize,
}
#[derive(Debug)]
enum Value {
    Text(String),
    Dict(BTreeMap<String, Node>),
    Array(Vec<Node>),
}
impl Node {
    fn dict(&self) -> Result<&BTreeMap<String, Node>> {
        if let Value::Dict(v) = &self.value {
            Ok(v)
        } else {
            bail!("expected OpenStep dictionary")
        }
    }
    fn text(&self) -> Result<&str> {
        if let Value::Text(v) = &self.value {
            Ok(v)
        } else {
            bail!("expected OpenStep string")
        }
    }
    fn array(&self) -> Result<&[Node]> {
        if let Value::Array(v) = &self.value {
            Ok(v)
        } else {
            bail!("expected OpenStep array")
        }
    }
    fn get(&self, key: &str) -> Result<&Node> {
        self.dict()?
            .get(key)
            .ok_or_else(|| anyhow!("missing Xcode field {key}"))
    }
    fn optional_text(&self, key: &str) -> Result<Option<&str>> {
        self.dict()?.get(key).map(Node::text).transpose()
    }
}
struct Parser<'a> {
    input: &'a [u8],
    at: usize,
    nodes: usize,
}
impl<'a> Parser<'a> {
    fn space(&mut self) -> Result<()> {
        loop {
            while self.input.get(self.at).is_some_and(u8::is_ascii_whitespace) {
                self.at += 1;
            }
            if self.input[self.at..].starts_with(b"//") {
                while self.input.get(self.at).is_some_and(|c| *c != b'\n') {
                    self.at += 1;
                }
            } else if self.input[self.at..].starts_with(b"/*") {
                self.at += 2;
                while !self.input[self.at..].starts_with(b"*/") {
                    if self.at == self.input.len() {
                        bail!("unterminated OpenStep comment");
                    }
                    self.at += 1;
                }
                self.at += 2;
            } else {
                return Ok(());
            }
        }
    }
    fn take(&mut self, c: u8) -> Result<()> {
        self.space()?;
        if self.input.get(self.at) != Some(&c) {
            bail!("invalid OpenStep delimiter at byte {}", self.at);
        }
        self.at += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<String> {
        self.space()?;
        if self.input.get(self.at) == Some(&b'"') {
            self.at += 1;
            let mut bytes = Vec::new();
            loop {
                let c = *self
                    .input
                    .get(self.at)
                    .ok_or_else(|| anyhow!("unterminated OpenStep string"))?;
                self.at += 1;
                match c {
                    b'"' => break,
                    b'\\' => {
                        let escaped = *self
                            .input
                            .get(self.at)
                            .ok_or_else(|| anyhow!("unterminated OpenStep escape"))?;
                        self.at += 1;
                        match escaped {
                            b'"' | b'\\' => bytes.push(escaped),
                            b'n' => bytes.push(b'\n'),
                            b'r' => bytes.push(b'\r'),
                            b't' => bytes.push(b'\t'),
                            // Refuse rather than misinterpret uncommon encodings.
                            _ => bail!("unsupported OpenStep string escape; project unchanged"),
                        }
                    }
                    0..=31 | 127 => bail!("control character in OpenStep string"),
                    _ => bytes.push(c),
                }
            }
            return Ok(String::from_utf8(bytes)?);
        }
        let start = self.at;
        while self
            .input
            .get(self.at)
            .is_some_and(|c| c.is_ascii_alphanumeric() || b"_./$<>+-".contains(c))
        {
            self.at += 1;
        }
        if start == self.at {
            bail!("unsupported OpenStep token at byte {}", self.at);
        }
        Ok(std::str::from_utf8(&self.input[start..self.at])?.to_owned())
    }
    fn node(&mut self, depth: usize) -> Result<Node> {
        self.nodes += 1;
        if depth > 128 || self.nodes > 500_000 {
            bail!("Xcode project parser limit exceeded");
        }
        self.space()?;
        let value = match self.input.get(self.at) {
            Some(b'{') => {
                self.at += 1;
                let mut entries = BTreeMap::new();
                loop {
                    self.space()?;
                    if self.input.get(self.at) == Some(&b'}') {
                        self.at += 1;
                        break;
                    }
                    let key = self.string()?;
                    self.take(b'=')?;
                    let value = self.node(depth + 1)?;
                    self.take(b';')?;
                    if entries.insert(key, value).is_some() {
                        bail!("duplicate OpenStep dictionary key");
                    }
                }
                Value::Dict(entries)
            }
            Some(b'(') => {
                self.at += 1;
                let mut items = Vec::new();
                loop {
                    self.space()?;
                    if self.input.get(self.at) == Some(&b')') {
                        self.at += 1;
                        break;
                    }
                    items.push(self.node(depth + 1)?);
                    self.space()?;
                    if self.input.get(self.at) == Some(&b')') {
                        self.at += 1;
                        break;
                    }
                    self.take(b',')?;
                }
                Value::Array(items)
            }
            _ => Value::Text(self.string()?),
        };
        Ok(Node {
            value,
            end: self.at,
        })
    }
}
fn parse(text: &str) -> Result<Node> {
    if text.len() > 8 * 1024 * 1024 {
        bail!("Xcode project exceeds 8 MiB limit");
    }
    let mut parser = Parser {
        input: text.as_bytes(),
        at: 0,
        nodes: 0,
    };
    let node = parser.node(0)?;
    parser.space()?;
    if parser.at != text.len() {
        bail!("trailing OpenStep input");
    }
    Ok(node)
}
fn relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("Xcode paths must be relative without parent traversal");
    }
    if path
        .to_str()
        .is_none_or(|s| s.chars().any(char::is_control))
    {
        bail!("Xcode paths must be UTF-8 without control characters");
    }
    Ok(())
}
fn quote(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}
fn normalized(base: &Path, path: &str) -> Option<PathBuf> {
    let mut result = base.to_path_buf();
    for part in Path::new(path).components() {
        match part {
            Component::Normal(p) => result.push(p),
            Component::CurDir => (),
            Component::ParentDir => {
                if !result.pop() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    Some(result)
}
fn location(node: &Node, parent: &Path) -> Result<Option<PathBuf>> {
    let base = match node.optional_text("sourceTree")?.unwrap_or("<group>") {
        "SOURCE_ROOT" => Path::new(""),
        "<group>" => parent,
        _ => return Ok(None),
    };
    Ok(normalized(base, node.optional_text("path")?.unwrap_or("")))
}
fn references(
    objects: &BTreeMap<String, Node>,
    group: &str,
    parent: &Path,
    visiting: &mut BTreeSet<String>,
    found: &mut BTreeSet<PathBuf>,
    depth: usize,
) -> Result<()> {
    if depth > 128 || !visiting.insert(group.to_owned()) {
        bail!("cyclic, multiply-parented or excessively deep Xcode groups");
    }
    let node = objects
        .get(group)
        .ok_or_else(|| anyhow!("missing Xcode group object"))?;
    let kind = node.get("isa")?.text()?;
    if kind == "PBXFileSystemSynchronizedRootGroup" {
        bail!("folder-synchronized Xcode groups already manage file discovery; registration is unsupported for this project");
    }
    if !["PBXGroup", "PBXVariantGroup", "XCVersionGroup"].contains(&kind) {
        bail!("unsupported Xcode group type {kind}");
    }
    let Some(base) = location(node, parent)? else {
        return Ok(());
    };
    for child in node.get("children")?.array()? {
        let id = child.text()?;
        let object = objects
            .get(id)
            .ok_or_else(|| anyhow!("missing Xcode child object"))?;
        match object.get("isa")?.text()? {
            "PBXGroup"
            | "PBXVariantGroup"
            | "XCVersionGroup"
            | "PBXFileSystemSynchronizedRootGroup" => {
                references(objects, id, &base, visiting, found, depth + 1)?
            }
            "PBXFileReference" => {
                if let Some(path) = location(object, &base)? {
                    found.insert(path);
                }
            }
            "PBXReferenceProxy" => (),
            // Unknown children may have build-specific path semantics.
            _ => bail!("unsupported Xcode navigator child type; project unchanged"),
        }
    }
    Ok(())
}

/// Add navigator references to a classic PBXGroup project. Build phases and
/// target membership are deliberately untouched. Returns insertion-only text.
/// Paths are workspace-relative, limited to files under the .xcodeproj parent.
pub fn register(text: &str, project: &Path, files: &[PathBuf]) -> Result<(String, usize)> {
    relative(project)?;
    if files.len() > 10_000 {
        bail!("too many files for one Xcode registration");
    }
    let parent = project
        .parent()
        .ok_or_else(|| anyhow!("missing Xcode project parent"))?;
    let root = parse(text)?;
    let objects_node = root.get("objects")?;
    let objects = objects_node.dict()?;
    let project_id = root.get("rootObject")?.text()?;
    let project_node = objects
        .get(project_id)
        .ok_or_else(|| anyhow!("missing PBXProject"))?;
    if project_node.get("isa")?.text()? != "PBXProject"
        || project_node
            .optional_text("projectDirPath")?
            .is_some_and(|p| !p.is_empty())
    {
        bail!("unsupported Xcode project root or nonempty projectDirPath");
    }
    let main = project_node.get("mainGroup")?.text()?;
    let main_node = objects
        .get(main)
        .ok_or_else(|| anyhow!("missing main group"))?;
    if main_node.get("isa")?.text()? != "PBXGroup" {
        bail!("main Xcode navigator must be a classic PBXGroup");
    }
    let children = main_node.get("children")?;
    let mut existing = BTreeSet::new();
    references(
        objects,
        main,
        Path::new(""),
        &mut BTreeSet::new(),
        &mut existing,
        0,
    )?;
    let mut additions = String::new();
    let mut ids = String::new();
    let mut used: BTreeSet<_> = objects.keys().cloned().collect();
    let mut count = 0;
    for file in files {
        relative(file)?;
        let path = file
            .strip_prefix(parent)
            .map_err(|_| anyhow!("file lies outside the selected .xcodeproj parent: {file:?}"))?;
        let path_text = path
            .to_str()
            .ok_or_else(|| anyhow!("non-UTF-8 Xcode path"))?;
        if existing.contains(path) {
            continue;
        }
        let mut salt = 0u32;
        let id = loop {
            let hash = Sha256::digest(format!("AgentVault-PBXFileReference:{path_text}:{salt}"));
            let id = hash[..12]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>();
            if used.insert(id.clone()) {
                break id;
            }
            salt = salt
                .checked_add(1)
                .ok_or_else(|| anyhow!("Xcode object ID collision limit"))?;
        };
        additions.push_str(&format!(
            "\n\t\t{id} = {{isa = PBXFileReference; path = {}; sourceTree = SOURCE_ROOT; }};\n",
            quote(path_text)
        ));
        ids.push_str(&format!("\n\t\t\t\t{id},\n"));
        existing.insert(path.to_path_buf());
        count += 1;
    }
    if count > 0 {
        if let Some(last) = children.array()?.last() {
            let mut tail = Parser {
                input: text.as_bytes(),
                at: last.end,
                nodes: 0,
            };
            tail.space()?;
            if tail.input.get(tail.at) != Some(&b',') {
                ids.insert(0, ',');
            }
        }
    }
    let mut result = text.to_owned();
    let mut edits = [(objects_node.end - 1, additions), (children.end - 1, ids)];
    edits.sort_by_key(|(offset, _)| std::cmp::Reverse(*offset));
    for (offset, insert) in edits {
        result.insert_str(offset, &insert);
    }
    parse(&result)?;
    Ok((result, count))
}
