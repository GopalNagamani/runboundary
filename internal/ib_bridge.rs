//! Per-build file IPC in the disposable home. The host reads typed data only.
pub mod assets;
pub mod client;
use crate::{
    interface_builder::build::{self, Files, Job},
    policy::config::Config,
    security::paths::Dir,
};
use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

const META_LIMIT: usize = 1024 * 1024;
const DATA_LIMIT: usize = 66 * 1024 * 1024;
const FRAME_LIMIT: u64 = (META_LIMIT + DATA_LIMIT + 4) as u64;
const ENTRY_LIMIT: usize = 4096;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInfo {
    path: PathBuf,
    size: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire<T> {
    version: u32,
    value: T,
    files: Vec<FileInfo>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    token: String,
    job: Job,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    ok: bool,
    stdout: String,
    stderr: String,
    error: Option<String>,
    stage_root: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    version: u32,
    token: String,
    workspace: PathBuf,
    derived: PathBuf,
}

fn verify_system_aliases() -> Result<()> {
    // Verify before launching untrusted build tasks. The sandboxed client uses
    // fixed spellings, not readlink/canonicalize on caller-controlled paths.
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        for (alias, relative, target) in [
            ("/var", "private/var", "/private/var"),
            ("/tmp", "private/tmp", "/private/tmp"),
        ] {
            let metadata = std::fs::symlink_metadata(alias)?;
            let actual = std::fs::read_link(alias)?;
            if metadata.uid() != 0
                || !metadata.file_type().is_symlink()
                || (actual != Path::new(relative) && actual != Path::new(target))
            {
                bail!("unexpected macOS system alias {alias:?}");
            }
        }
    }
    Ok(())
}

fn encode<T: Serialize>(value: T, files: &Files) -> Result<Vec<u8>> {
    if files.len() > ENTRY_LIMIT {
        bail!("bridge file-count limit exceeded");
    }
    let mut total = 0usize;
    for bytes in files.values() {
        total = total
            .checked_add(bytes.len())
            .context("bridge size overflow")?;
    }
    if total > DATA_LIMIT {
        bail!("bridge payload limit exceeded");
    }
    let header = serde_json::to_vec(&Wire {
        version: 1,
        value,
        files: files
            .iter()
            .map(|(path, bytes)| FileInfo {
                path: path.clone(),
                size: bytes.len(),
            })
            .collect(),
    })?;
    if header.len() > META_LIMIT {
        bail!("bridge metadata limit exceeded");
    }
    let mut out = Vec::with_capacity(4 + header.len() + total);
    out.extend_from_slice(&(header.len() as u32).to_be_bytes());
    out.extend(header);
    for bytes in files.values() {
        out.extend_from_slice(bytes);
    }
    Ok(out)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<(T, Files)> {
    if bytes.len() < 4 || bytes.len() as u64 > FRAME_LIMIT {
        bail!("invalid bridge frame length");
    }
    let len = u32::from_be_bytes(bytes[..4].try_into()?) as usize;
    if len > META_LIMIT || 4 + len > bytes.len() {
        bail!("invalid bridge metadata length");
    }
    let wire: Wire<T> = serde_json::from_slice(&bytes[4..4 + len])?;
    if wire.version != 1 || wire.files.len() > ENTRY_LIMIT {
        bail!("unsupported bridge version or file count");
    }
    let mut offset = 4 + len;
    let mut files = Files::new();
    for file in wire.files {
        crate::interface_builder::validate_relative_file(&file.path)?;
        let end = offset
            .checked_add(file.size)
            .context("bridge size overflow")?;
        if end > bytes.len() || end - (4 + len) > DATA_LIMIT || files.contains_key(&file.path) {
            bail!("invalid bridge file size or duplicate path");
        }
        files.insert(file.path, bytes[offset..end].to_vec());
        offset = end;
    }
    if offset != bytes.len() {
        bail!("unexpected trailing bridge data");
    }
    Ok((wire.value, files))
}
fn nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn authenticated(a: &str, b: &str) -> bool {
    a.len() == 64
        && b.len() == 64
        && a.bytes().zip(b.bytes()).fold(0u8, |v, (a, b)| v | (a ^ b)) == 0
}
fn atomic_write(dir: &Dir, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = PathBuf::from(format!("{name}.tmp-{}", nonce()?));
    dir.create(&temporary, bytes, 0o600)?;
    let result = dir.rename(&temporary, dir, Path::new(name));
    if result.is_err() {
        let _ = dir.remove(&temporary);
    }
    result
}
pub struct Broker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<()>>>,
    pub wrapper: PathBuf,
    pub asset_wrapper: PathBuf,
}
impl Broker {
    pub fn start(
        project: &Path,
        config: &Config,
        runtime: &Path,
        workspace: &Path,
        home: &Path,
        services: crate::interface_builder::SimulatorServices,
    ) -> Result<Self> {
        let ios = config
            .toolchains
            .ios
            .as_ref()
            .context("approve Xcode before starting the bridge")?;
        let mut compiler_config = Config::for_host();
        compiler_config.toolchains.ios = Some(crate::policy::toolchains::Ios {
            xcode_app: ios.xcode_app.clone(),
        });
        let root = project.to_owned();
        let runtime = crate::interface_builder::approve_runtime(runtime)?;
        Self::prepare(workspace, home, move |job, files, cancel| {
            build::execute_with_services(
                &root,
                &compiler_config,
                &runtime,
                job,
                files,
                cancel,
                services,
            )
        })
    }
    fn prepare<F>(workspace: &Path, home: &Path, handler: F) -> Result<Self>
    where
        F: Fn(&Job, &Files, &AtomicBool) -> Result<build::Output> + Send + 'static,
    {
        verify_system_aliases()?;
        let home = home.canonicalize()?;
        // The runtime and compiler configuration stay captured in the host
        // worker. Shared state never chooses a host executable, path or runtime.
        let bridge = home.join(".agentvault-ib");
        Dir::open(&home)?.mkdir(std::ffi::OsStr::new(".agentvault-ib"))?;
        let dir = Dir::open(&bridge)?;
        dir.mkdir(std::ffi::OsStr::new("queue"))?;
        let queue = Dir::open(&bridge.join("queue"))?;
        let settings = Settings {
            version: 1,
            token: nonce()?,
            workspace: workspace.canonicalize()?,
            derived: home.join("build/DerivedData"),
        };
        dir.create(
            Path::new("settings.json"),
            &serde_json::to_vec(&settings)?,
            0o600,
        )?;
        std::fs::copy(std::env::current_exe()?, bridge.join("client"))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            bridge.join("client"),
            std::fs::Permissions::from_mode(0o700),
        )?;
        dir.create(Path::new("ibtool"),b"#!/bin/sh\nbridge=${0%/*}\nexec \"$bridge/client\" ibtool-client --bridge \"$bridge\" -- \"$@\"\n",0o700)?;
        dir.create(Path::new("actool"),b"#!/bin/sh\nbridge=${0%/*}\nexec \"$bridge/client\" actool-client --bridge \"$bridge\" -- \"$@\"\n",0o700)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            let result = (|| -> Result<()> {
                let mut requests = 0usize;
                while !stopped.load(Ordering::Relaxed) {
                    let entries = queue.entries()?;
                    if entries.len() > 128 {
                        bail!("Interface Builder queue budget exceeded");
                    }
                    for path in entries {
                        if stopped.load(Ordering::Relaxed) {
                            break;
                        }
                        let Some(name) = path.to_str() else {
                            bail!("invalid bridge queue entry");
                        };
                        let Some(id) = name
                            .strip_prefix("req-")
                            .and_then(|s| s.strip_suffix(".frame"))
                        else {
                            continue;
                        };
                        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                            bail!("invalid bridge request name");
                        }
                        requests += 1;
                        if requests > 1024 {
                            bail!("Interface Builder request budget exceeded");
                        }
                        let reply = (|| -> Result<_> {
                            let bytes = queue.read_file(&path, FRAME_LIMIT)?.0;
                            let (request, files) = decode::<Request>(&bytes)?;
                            if !authenticated(&settings.token, &request.token) {
                                bail!("bridge authentication rejected");
                            }
                            request.job.validate(&files)?;
                            let output = handler(&request.job, &files, &stopped)?;
                            eprintln!(
                                "Interface Builder broker completed {}",
                                match request.job {
                                    Job::Version { .. } => "version query",
                                    Job::Compile { .. } => "compile",
                                    Job::Link { .. } => "link",
                                    Job::AssetVersion { .. } => "asset version query",
                                    Job::AssetTagCombinations { .. } => "asset tag query",
                                    Job::AssetCatalog { .. } => "asset catalog",
                                }
                            );
                            Ok(output)
                        })();
                        let (meta, files) = match reply {
                            Ok(output) => (
                                Reply {
                                    ok: true,
                                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                                    error: None,
                                    stage_root: output.stage_root,
                                },
                                output.files,
                            ),
                            Err(error) => (
                                Reply {
                                    ok: false,
                                    stdout: String::new(),
                                    stderr: String::new(),
                                    error: Some(format!("{error:#}").chars().take(16384).collect()),
                                    stage_root: String::new(),
                                },
                                Files::new(),
                            ),
                        };
                        atomic_write(&queue, &format!("reply-{id}.frame"), &encode(meta, &files)?)?;
                        queue.remove(&path)?;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(())
            })();
            if let Err(error) = &result {
                let _ = queue.create(Path::new("fatal"), format!("{error:#}").as_bytes(), 0o600);
            }
            result
        });
        Ok(Self {
            stop,
            thread: Some(thread),
            wrapper: bridge.join("ibtool"),
            asset_wrapper: bridge.join("actool"),
        })
    }
    pub fn finish(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread
            .take()
            .context("missing broker worker")?
            .join()
            .map_err(|_| anyhow::anyhow!("Interface Builder worker panicked"))?
    }
}
impl Drop for Broker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn exchange(bridge: &Path, job: Job, files: &Files) -> Result<(Reply, Files)> {
    let dir = client::open_root(bridge)?;
    let settings: Settings = serde_json::from_slice(
        &dir.read_file("settings.json", 8192)
            .context("read Interface Builder transport settings")?
            .0,
    )?;
    if settings.version != 1 {
        bail!("unsupported bridge settings");
    }
    let queue = dir
        .child(std::ffi::OsStr::new("queue"))
        .context("open Interface Builder request queue")?;
    let id = nonce()?;
    let response = PathBuf::from(format!("reply-{id}.frame"));
    let bytes = encode(
        Request {
            token: settings.token,
            job,
        },
        files,
    )?;
    atomic_write(&queue, &format!("req-{id}.frame"), &bytes)
        .context("publish Interface Builder request")?;
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        match queue.read_file(&response, FRAME_LIMIT) {
            Ok((bytes, _)) => {
                let reply = decode(&bytes)?;
                queue.remove(&response)?;
                return Ok(reply);
            }
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .and_then(|e| e.raw_os_error())
                    == Some(libc::ENOENT) => {}
            Err(e) => return Err(e).context("read Interface Builder reply"),
        }
        if let Ok((error, _)) = queue.read_file("fatal", 16384) {
            bail!(
                "Interface Builder worker failed: {}",
                String::from_utf8_lossy(&error).escape_debug()
            );
        }
        if Instant::now() >= deadline {
            bail!("Interface Builder reply deadline exceeded");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface_builder::build::Format;
    use std::sync::atomic::AtomicUsize;

    #[cfg(target_os = "macos")]
    #[test]
    fn xcode_system_alias_can_query_a_bridge_with_canonical_private_home_settings() {
        let temp = tempfile::tempdir_in("/private/tmp").unwrap();
        let home = temp.path().canonicalize().unwrap();
        let work = home.join("workspace");
        std::fs::create_dir(&work).unwrap();
        let broker = Broker::prepare(&work, &home, |_, _, _| {
            Ok(build::Output {
                files: Files::new(),
                stdout: b"version alias fixture\n".to_vec(),
                stderr: vec![],
                stage_root: String::new(),
            })
        })
        .unwrap();
        let canonical = broker.wrapper.parent().unwrap();
        let alias = Path::new("/").join(canonical.strip_prefix("/private").expect(
            "macOS temporary directory must have a canonical /private path for this regression",
        ));
        assert_ne!(canonical, alias);
        assert_eq!(
            canonical.canonicalize().unwrap(),
            alias.canonicalize().unwrap()
        );
        assert_eq!(
            client::execute(
                &alias,
                &["--version".into(), "--output-format".into(), "xml1".into()]
            )
            .unwrap(),
            0
        );
        broker.finish().unwrap();
    }

    #[test]
    fn frames_reject_traversal_duplicates_truncation_unknown_versions_and_size_overflow() {
        let files = Files::from([(PathBuf::from("Sample.xib"), b"sample".to_vec())]);
        let bytes = encode(17u32, &files).unwrap();
        let (value, decoded) = decode::<u32>(&bytes).unwrap();
        assert_eq!(value, 17);
        assert_eq!(decoded, files);
        for cut in [0, 3, bytes.len() - 1] {
            assert!(decode::<u32>(&bytes[..cut]).is_err());
        }
        let frame = |header: serde_json::Value| {
            let header = serde_json::to_vec(&header).unwrap();
            let mut bytes = (header.len() as u32).to_be_bytes().to_vec();
            bytes.extend(header);
            bytes
        };
        for header in [
            serde_json::json!({"version":2,"value":17,"files":[]}),
            serde_json::json!({"version":1,"value":17,"files":[{"path":"../secret","size":0}]}),
            serde_json::json!({"version":1,"value":17,"files":[{"path":"/host/secret","size":0}]}),
            serde_json::json!({"version":1,"value":17,"files":[{"path":"a","size":0},{"path":"a","size":0}]}),
            serde_json::json!({"version":1,"value":17,"files":[{"path":"a","size":usize::MAX}]}),
        ] {
            assert!(decode::<u32>(&frame(header)).is_err());
        }
        let mut extra = bytes;
        extra.push(1);
        assert!(decode::<u32>(&extra).is_err());
    }

    fn wait_reply(queue: &Dir, id: &str) -> Reply {
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok((bytes, _)) = queue.read_file(format!("reply-{id}.frame"), FRAME_LIMIT) {
                let (reply, _) = decode(&bytes).unwrap();
                queue
                    .remove(Path::new(&format!("reply-{id}.frame")))
                    .unwrap();
                return reply;
            }
            assert!(Instant::now() < end, "reply did not arrive");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn real_file_transport_authenticates_and_never_follows_request_symlinks() {
        // The handler is a protocol fixture, not an OS compiler/isolation test.
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("workspace");
        std::fs::create_dir(&work).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = calls.clone();
        let broker = Broker::prepare(&work, temp.path(), move |_, _, _| {
            called.fetch_add(1, Ordering::Relaxed);
            Ok(build::Output {
                files: Files::new(),
                stdout: b"version fixture".to_vec(),
                stderr: vec![],
                stage_root: String::new(),
            })
        })
        .unwrap();
        let bridge = broker.wrapper.parent().unwrap();
        let (reply, files) = exchange(
            bridge,
            Job::Version {
                format: Format::Xml,
            },
            &Files::new(),
        )
        .unwrap();
        assert!(reply.ok);
        assert!(files.is_empty());
        assert_eq!(reply.stdout, "version fixture");
        let queue = Dir::open(&bridge.join("queue")).unwrap();
        let id = nonce().unwrap();
        let forged = encode(
            Request {
                token: "0".repeat(64),
                job: Job::Version {
                    format: Format::Xml,
                },
            },
            &Files::new(),
        )
        .unwrap();
        atomic_write(&queue, &format!("req-{id}.frame"), &forged).unwrap();
        let reply = wait_reply(&queue, &id);
        assert!(!reply.ok);
        assert!(reply.error.unwrap().contains("authentication"));
        let secret = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(secret.path(), b"SYNTHETIC_OUTSIDE_BRIDGE_CANARY").unwrap();
        let id = nonce().unwrap();
        std::os::unix::fs::symlink(
            secret.path(),
            bridge.join("queue").join(format!("req-{id}.frame")),
        )
        .unwrap();
        let reply = wait_reply(&queue, &id);
        assert!(!reply.ok);
        assert!(!reply
            .error
            .unwrap()
            .contains("SYNTHETIC_OUTSIDE_BRIDGE_CANARY"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        broker.finish().unwrap();
    }

    #[test]
    fn stopping_a_build_cancels_an_in_flight_handler_and_joins_the_worker() {
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("workspace");
        std::fs::create_dir(&work).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let broker = Broker::prepare(&work, temp.path(), move |_, _, stop| {
            started_tx.send(()).unwrap();
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(5));
            }
            bail!("cancelled fixture")
        })
        .unwrap();
        let bridge = broker.wrapper.parent().unwrap().to_owned();
        let client = std::thread::spawn(move || {
            exchange(
                &bridge,
                Job::Version {
                    format: Format::Xml,
                },
                &Files::new(),
            )
        });
        started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let now = Instant::now();
        broker.finish().unwrap();
        assert!(now.elapsed() < Duration::from_secs(2));
        assert!(!client.join().unwrap().unwrap().0.ok);
    }

    #[test]
    fn asset_tag_queries_read_catalog_directories_without_creating_build_outputs() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let work = home.join("workspace");
        let catalog = work.join("Assets.xcassets");
        std::fs::create_dir_all(&catalog).unwrap();
        std::fs::write(catalog.join("Contents.json"), b"{}").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = calls.clone();
        let broker = Broker::prepare(&work, &home, move |job, files, _| {
            let Job::AssetTagCombinations { catalogs } = job else {
                bail!("expected asset tag query")
            };
            assert_eq!(catalogs, &["Assets.xcassets"]);
            assert_eq!(files, &Files::from([
                (PathBuf::from("Assets.xcassets/Contents.json"), b"{}".to_vec())
            ]));
            called.fetch_add(1, Ordering::Relaxed);
            Ok(build::Output {
                files: Files::new(),
                stdout: b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>com.apple.actool.asset-tag-combinations</key><array/></dict></plist>".to_vec(),
                stderr: vec![],
                stage_root: "/stage".into(),
            })
        }).unwrap();
        let bridge = broker.wrapper.parent().unwrap();
        let args = vec![
            "--print-asset-tag-combinations".into(),
            "--output-format".into(),
            "xml1".into(),
            catalog.to_str().unwrap().into(),
        ];
        let secret = home.join("outside.json");
        std::fs::write(&secret, b"outside catalog").unwrap();
        std::os::unix::fs::symlink(&secret, catalog.join("linked.json")).unwrap();
        assert!(client::execute_assets(bridge, &args).is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        std::fs::remove_file(catalog.join("linked.json")).unwrap();
        assert_eq!(client::execute_assets(bridge, &args).unwrap(), 0);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(!home.join("build/DerivedData").exists());
        broker.finish().unwrap();
    }

    #[test]
    fn asset_transport_bounds_catalog_reads_and_publishes_car_and_symbol_outputs() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let work = home.join("workspace");
        let catalog = work.join("Assets.xcassets");
        let derived = home.join("build/DerivedData");
        let app = derived.join("Products/App.app");
        std::fs::create_dir_all(&catalog).unwrap();
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(catalog.join("Contents.json"), b"{}").unwrap();
        std::fs::write(app.join("executable"), b"existing product").unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = calls.clone();
        let broker = Broker::prepare(&work, &home, move |job, files, _| {
            let Job::AssetCatalog { catalogs, options } = job else { bail!("unexpected operation") };
            assert_eq!(catalogs, &["Assets.xcassets"]);
            assert_eq!(files, &Files::from([(PathBuf::from("Assets.xcassets/Contents.json"), b"{}".to_vec())]));
            called.fetch_add(1, Ordering::Relaxed);
            let files = if options.symbols() {
                Files::from([
                    (PathBuf::from("Aux/asset-symbols.swift"), b"Swift symbols".to_vec()),
                    (PathBuf::from("Aux/asset-symbols.h"), b"ObjC symbols".to_vec()),
                    (PathBuf::from("Aux/asset-symbol-index.plist"), b"index".to_vec()),
                ])
            } else {
                Files::from([
                    (PathBuf::from("Outputs/Assets.car"), b"CAR fixture".to_vec()),
                    (PathBuf::from("Outputs/AppIcon60x60@2x.png"), b"PNG fixture".to_vec()),
                    (PathBuf::from("Aux/partial.plist"), b"metadata".to_vec()),
                    (PathBuf::from("Aux/dependencies"), b"\0fixture\0\x10/stage/Inputs/Assets.xcassets/Contents.json\0\x40/stage/Outputs/Assets.car\0\x40/stage/Aux/partial.plist\0".to_vec()),
                ])
            };
            Ok(build::Output { files, stdout: vec![], stderr: vec![], stage_root: "/stage".into() })
        }).unwrap();
        let bridge = broker.wrapper.parent().unwrap();
        let mut args = vec![
            catalog.to_str().unwrap().into(),
            "--compile".into(),
            home.join("outside").to_str().unwrap().into(),
            "--output-partial-info-plist".into(),
            derived.join("Temp/Assets.plist").to_str().unwrap().into(),
            "--export-dependency-info".into(),
            derived.join("Temp/Assets.dep").to_str().unwrap().into(),
        ];
        assert!(client::execute_assets(bridge, &args).is_err());
        args[2] = app.to_str().unwrap().into();
        let outside = home.join("outside.png");
        std::fs::write(&outside, b"outside asset").unwrap();
        std::os::unix::fs::symlink(&outside, catalog.join("linked.png")).unwrap();
        assert!(client::execute_assets(bridge, &args).is_err());
        std::fs::remove_file(catalog.join("linked.png")).unwrap();
        let alias = work.join("Alias.xcassets");
        std::os::unix::fs::symlink(&catalog, &alias).unwrap();
        args[0] = alias.to_str().unwrap().into();
        assert!(client::execute_assets(bridge, &args).is_err());
        args[0] = catalog.to_str().unwrap().into();
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        client::execute_assets(bridge, &args).unwrap();
        assert_eq!(
            std::fs::read(app.join("Assets.car")).unwrap(),
            b"CAR fixture"
        );
        assert_eq!(
            std::fs::read(app.join("executable")).unwrap(),
            b"existing product"
        );
        let dependencies = std::fs::read(derived.join("Temp/Assets.dep")).unwrap();
        let expected = format!(
            "\0fixture\0\x10{}/Contents.json\0\x40{}/Assets.car\0\x40{}/Temp/Assets.plist\0",
            catalog.display(),
            app.display(),
            derived.display()
        );
        assert_eq!(dependencies, expected.as_bytes());
        let mut symbols: Vec<String> = vec![
            catalog.to_str().unwrap().into(),
            "--compile".into(),
            app.to_str().unwrap().into(),
        ];
        for (flag, name) in [
            ("--generate-swift-asset-symbols", "Symbols.swift"),
            ("--generate-objc-asset-symbols", "Symbols.h"),
            ("--generate-asset-symbol-index", "Symbols.plist"),
        ] {
            symbols.extend([
                flag.into(),
                derived.join("Sources").join(name).to_str().unwrap().into(),
            ]);
        }
        let valid = symbols[4].clone();
        symbols[4] = home.join("outside.swift").to_str().unwrap().into();
        assert!(client::execute_assets(bridge, &symbols).is_err());
        assert!(!home.join("outside.swift").exists());
        symbols[4] = valid;
        client::execute_assets(bridge, &symbols).unwrap();
        assert_eq!(
            std::fs::read(derived.join("Sources/Symbols.swift")).unwrap(),
            b"Swift symbols"
        );
        assert_eq!(
            std::fs::read(derived.join("Sources/Symbols.h")).unwrap(),
            b"ObjC symbols"
        );
        assert_eq!(
            std::fs::read(derived.join("Sources/Symbols.plist")).unwrap(),
            b"index"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        broker.finish().unwrap();
    }

    #[test]
    fn localized_compile_and_link_preserve_bytes_and_publish_into_existing_locale_directories() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let work = home.join("workspace");
        let derived = home.join("build/DerivedData");
        for dir in [
            &work,
            &derived.join("Temp/Base.lproj"),
            &derived.join("Temp/zh-Hans.lproj"),
            &derived.join("Products/App.app/Base.lproj"),
            &derived.join("Products/App.app/zh-Hans.lproj"),
            &work.join("zh-Hans.lproj"),
        ] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let source = work.join("Sample.storyboard");
        std::fs::write(
            &source,
            include_bytes!("../tests/fixtures/ib_build/LaunchScreen.storyboard"),
        )
        .unwrap();
        let strings = work.join("zh-Hans.lproj/Sample.strings");
        let translation = b"\"label.text\" = \"Translated\";";
        std::fs::write(&strings, translation).unwrap();
        let outside = home.join("outside.strings");
        std::fs::write(&outside, translation).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = calls.clone();
        let broker = Broker::prepare(&work, &home, move |job, files, _| {
            if let Job::Link { inputs, .. } = job {
                assert_eq!(inputs, &["Base.lproj/Sample.storyboardc"]);
                assert_eq!(files[Path::new("Base.lproj/Sample.storyboardc/AgentVaultLocalization/zh-Hans/Sample.strings")], translation);
                called.fetch_add(1, Ordering::Relaxed);
                return Ok(build::Output {
                    files: Files::from([
                        (PathBuf::from("Outputs/Base.lproj/Sample.storyboardc/Info.plist"), b"linked storyboard fixture".to_vec()),
                        (PathBuf::from("Outputs/zh-Hans.lproj/Sample.strings"), translation.to_vec()),
                    ]),
                    stdout: vec![], stderr: vec![], stage_root: "/link-stage".into(),
                });
            }
            let Job::Compile { options, .. } = job else { bail!("unexpected operation") };
            assert_eq!(options.companion_locales, ["zh-Hans"]);
            assert_eq!(files.len(), 2);
            assert_eq!(files[Path::new("Strings/zh-Hans.strings")], translation);
            called.fetch_add(1, Ordering::Relaxed);
            Ok(build::Output {
                files: Files::from([
                    (PathBuf::from("Outputs/Base.lproj/Sample.storyboardc/Info.plist"), b"storyboard fixture".to_vec()),
                    (PathBuf::from("Outputs/Base.lproj/Sample.storyboardc/AgentVaultLocalization/locales.json"), b"[\"zh-Hans\"]".to_vec()),
                    (PathBuf::from("Outputs/Base.lproj/Sample.storyboardc/AgentVaultLocalization/zh-Hans/Sample.strings"), translation.to_vec()),
                    (PathBuf::from("Aux/dependencies"), b"\0fixture\0\x10/stage/Inputs/Sample.storyboard\0\x10/stage/Inputs/Strings/zh-Hans.strings\0\x40/stage/Outputs/Base.lproj/Sample.storyboardc/Info.plist\0\x40/stage/Outputs/Base.lproj/Sample.storyboardc/AgentVaultLocalization/zh-Hans/Sample.strings\0".to_vec()),
                ]),
                stdout: vec![], stderr: vec![], stage_root: "/stage".into(),
            })
        }).unwrap();
        let bridge = broker.wrapper.parent().unwrap();
        let dependencies = derived.join("Temp/Sample.dep");
        let args = |companion: &Path| {
            vec![
                "--companion-strings-file".into(),
                format!("zh-Hans:{}", companion.display()),
                "--generate-dependency-info".into(),
                dependencies.to_str().unwrap().into(),
                "--compilation-directory".into(),
                derived.join("Temp/Base.lproj").to_str().unwrap().into(),
                source.to_str().unwrap().into(),
            ]
        };
        assert!(client::execute(bridge, &args(&outside)).is_err());
        let link = work.join("linked.strings");
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        assert!(client::execute(bridge, &args(&link)).is_err());
        let ancestor = work.join("alias");
        std::os::unix::fs::symlink(work.join("zh-Hans.lproj"), &ancestor).unwrap();
        assert!(client::execute(bridge, &args(&ancestor.join("Sample.strings"))).is_err());
        assert!(client::execute(
            bridge,
            &args(&work.join("zh-Hans.lproj/../zh-Hans.lproj/Sample.strings"))
        )
        .is_err());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(client::execute(bridge, &args(&strings)).unwrap(), 0);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            std::fs::read(derived.join("Temp/Base.lproj/Sample.storyboardc/Info.plist")).unwrap(),
            b"storyboard fixture"
        );
        assert_eq!(
            std::fs::read(derived.join(
                "Temp/Base.lproj/Sample.storyboardc/AgentVaultLocalization/zh-Hans/Sample.strings"
            ))
            .unwrap(),
            translation
        );
        let records = std::fs::read(&dependencies).unwrap();
        let expected = format!("\0fixture\0\x10{}\0\x10{}\0\x40{}/Temp/Base.lproj/Sample.storyboardc/Info.plist\0\x40{}/Temp/Base.lproj/Sample.storyboardc/AgentVaultLocalization/zh-Hans/Sample.strings\0", source.display(), strings.display(), derived.display(), derived.display());
        assert_eq!(records, expected.as_bytes());
        client::execute(
            bridge,
            &[
                "--link".into(),
                derived.join("Products/App.app").to_str().unwrap().into(),
                derived
                    .join("Temp/Base.lproj/Sample.storyboardc")
                    .to_str()
                    .unwrap()
                    .into(),
            ],
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            std::fs::read(
                derived.join("Products/App.app/Base.lproj/Sample.storyboardc/Info.plist")
            )
            .unwrap(),
            b"linked storyboard fixture"
        );
        assert_eq!(
            std::fs::read(derived.join("Products/App.app/zh-Hans.lproj/Sample.strings")).unwrap(),
            translation
        );
        broker.finish().unwrap();
    }

    #[test]
    fn client_publishes_bytes_and_remapped_side_files_only_inside_derived_data() {
        // End-to-end adapter/transport/publication regression with a data-only
        // handler. Real Apple compilation is tested separately in Terminal.
        let temp = tempfile::tempdir().unwrap();
        let work = temp.path().join("workspace");
        let home = temp.path().join("home");
        std::fs::create_dir(&work).unwrap();
        std::fs::create_dir(&home).unwrap();
        let work = work.canonicalize().unwrap();
        let home = home.canonicalize().unwrap();
        std::fs::write(
            work.join("Sample.xib"),
            include_bytes!("../tests/fixtures/interface_builder.xib"),
        )
        .unwrap();
        let derived = home.join("build/DerivedData");
        std::fs::create_dir_all(&derived).unwrap();
        let called = Arc::new(AtomicUsize::new(0));
        let calls = called.clone();
        let broker=Broker::prepare(&work,&home,move |job,files,_| {
            let Job::Compile{input,output,options,..}=job else {bail!("unexpected operation");};
            assert_eq!(input,"Sample.xib");assert_eq!(output,"Sample.nib");assert_eq!(files.len(),1);
            assert!(options.partial_info && options.dependencies);calls.fetch_add(1,Ordering::Relaxed);
            Ok(build::Output{files:Files::from([
                (PathBuf::from("Outputs/Sample.nib"),b"NIB artifact fixture".to_vec()),
                (PathBuf::from("Aux/partial.plist"),b"plist fixture".to_vec()),
                (PathBuf::from("Aux/dependencies"),b"\0fixture\0\x10/stage/Inputs/Sample.xib\0\x40/stage/Outputs/Sample.nib\0\x40/stage/Aux/partial.plist\0".to_vec()),
            ]),stdout:vec![],stderr:vec![],stage_root:"/stage".into()})
        }).unwrap();
        let bridge = broker.wrapper.parent().unwrap();
        let output = derived.join("Products/App.app/Sample.nib");
        let partial = derived.join("Temp/Sample.plist");
        let dep = derived.join("Temp/Sample.dep");
        let mut args = vec![
            "--output-partial-info-plist".into(),
            partial.to_str().unwrap().into(),
            "--generate-dependency-info".into(),
            dep.to_str().unwrap().into(),
            "--compile".into(),
            temp.path().join("outside.nib").to_str().unwrap().into(),
            work.join("Sample.xib").to_str().unwrap().into(),
        ];
        assert!(client::execute(bridge, &args).is_err());
        assert_eq!(called.load(Ordering::Relaxed), 0);
        assert!(!temp.path().join("outside.nib").exists());
        args[5] = output.to_str().unwrap().into();
        let alias = |path: &Path| {
            #[cfg(target_os = "macos")]
            if path.starts_with("/private/var") || path.starts_with("/private/tmp") {
                return Path::new("/").join(path.strip_prefix("/private").unwrap());
            }
            path.to_owned()
        };
        args[1] = alias(&partial).to_str().unwrap().into();
        args[3] = alias(&dep).to_str().unwrap().into();
        args[5] = alias(&output).to_str().unwrap().into();
        args[6] = alias(&work.join("Sample.xib")).to_str().unwrap().into();
        assert_eq!(client::execute(&alias(bridge), &args).unwrap(), 0);
        assert_eq!(std::fs::read(&output).unwrap(), b"NIB artifact fixture");
        assert_eq!(std::fs::read(&partial).unwrap(), b"plist fixture");
        let dependencies = std::fs::read(&dep).unwrap();
        assert!(!dependencies.windows(6).any(|b| b == b"/stage"));
        assert!(dependencies
            .windows(partial.to_str().unwrap().len())
            .any(|b| b == partial.to_str().unwrap().as_bytes()));
        assert_eq!(called.load(Ordering::Relaxed), 1);
        let outside = tempfile::tempdir().unwrap();
        std::fs::rename(&derived, home.join("build/SavedData")).unwrap();
        std::os::unix::fs::symlink(outside.path(), &derived).unwrap();
        assert!(client::execute(bridge, &args).is_err());
        assert!(!outside.path().join("Temp/Sample.plist").exists());
        assert!(!outside.path().join("Products/App.app/Sample.nib").exists());
        broker.finish().unwrap();
    }
}
