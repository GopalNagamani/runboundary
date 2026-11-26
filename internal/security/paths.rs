//! Descriptor-relative traversal. Never follow project or output symlinks.
use anyhow::{bail, Context, Result};
use std::{
    ffi::{CStr, CString, OsStr},
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
};
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Identity {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub links: u64,
    pub size: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub mtime_ns: i64,
    pub ctime_ns: i64,
}
impl Identity {
    #[allow(clippy::unnecessary_cast)] // libc field widths differ between supported development targets.
    fn from(s: libc::stat) -> Self {
        Self {
            dev: s.st_dev as u64,
            ino: s.st_ino as u64,
            mode: s.st_mode as u32,
            links: s.st_nlink as u64,
            size: s.st_size,
            mtime: s.st_mtime,
            ctime: s.st_ctime,
            mtime_ns: s.st_mtime_nsec,
            ctime_ns: s.st_ctime_nsec,
        }
    }
    pub fn regular(&self) -> bool {
        self.has_type(libc::S_IFREG)
    }
    pub fn symlink(&self) -> bool {
        self.has_type(libc::S_IFLNK)
    }
    pub fn directory(&self) -> bool {
        self.has_type(libc::S_IFDIR)
    }
    fn has_type(&self, kind: libc::mode_t) -> bool {
        // Linux mode_t is u32; macOS mode_t is u16. Compare native types so
        // strict Linux Clippy does not flag the macOS widening conversions.
        #[cfg(target_os = "linux")]
        let mode = self.mode;
        #[cfg(target_os = "macos")]
        let mode = self.mode as libc::mode_t;
        mode & libc::S_IFMT == kind
    }
}
fn c(p: &OsStr) -> Result<CString> {
    Ok(CString::new(p.as_bytes())?)
}
fn cv(fd: i32) -> Result<File> {
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn stat(f: &File) -> Result<Identity> {
    let mut s = std::mem::MaybeUninit::uninit();
    if unsafe { libc::fstat(f.as_raw_fd(), s.as_mut_ptr()) } != 0 {
        bail!(std::io::Error::last_os_error());
    }
    Ok(Identity::from(unsafe { s.assume_init() }))
}
pub struct Dir {
    file: File,
}
impl Dir {
    /// Pin an absolute directory without reading or following its ancestors.
    /// Only the final directory is opened for reading. This also works when
    /// ancestor permissions allow searching but forbid directory enumeration.
    pub fn open_absolute(p: &Path) -> Result<Self> {
        if !p.is_absolute() {
            bail!("directory root must be absolute");
        }
        let mut names = Vec::new();
        for component in p.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => names.push(name),
                _ => bail!("unsafe absolute directory path"),
            }
        }
        #[cfg(target_os = "macos")]
        let search = libc::O_SEARCH;
        #[cfg(target_os = "linux")]
        let search = libc::O_PATH | libc::O_DIRECTORY;
        let flags = search | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let mut dir = Self {
            file: cv(unsafe { libc::open(c(OsStr::new("/"))?.as_ptr(), flags) })
                .context("open filesystem root for directory search")?,
        };
        let mut traversed = PathBuf::from("/");
        for name in names {
            traversed.push(name);
            dir = Self {
                file: cv(unsafe { libc::openat(dir.file.as_raw_fd(), c(name)?.as_ptr(), flags) })
                    .with_context(|| {
                    format!("search directory {traversed:?} without following links")
                })?,
            };
        }
        dir.child(OsStr::new("."))
            .with_context(|| format!("open directory {p:?} for reading"))
    }
    pub fn open(p: &Path) -> Result<Self> {
        let p = c(p.as_os_str())?;
        Ok(Self {
            file: cv(unsafe {
                libc::open(
                    p.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?,
        })
    }
    /// A persistent per-session advisory lock, inaccessible to sandboxed code.
    /// Never unlink lock files: waiters must continue to share the same inode.
    pub fn lock(&self, path: &Path) -> Result<File> {
        let (dir, name) = self.parent(path)?;
        let name = c(&name)?;
        let file = cv(unsafe {
            libc::openat(
                dir.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        })?;
        let meta = stat(&file)?;
        if !meta.regular() || meta.links != 1 || meta.mode & 0o077 != 0 {
            bail!("unsafe session lock file");
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("session is busy; stop its preview or review operation before retrying");
        }
        Ok(file)
    }
    pub fn sync(&self) -> Result<()> {
        self.file.sync_all()?;
        Ok(())
    }
    pub fn identity(&self) -> Result<Identity> {
        stat(&self.file)
    }

    /// Return bytes available to this user and the allocation block size.
    pub(crate) fn filesystem_space(&self) -> Result<(u128, u128)> {
        let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::fstatvfs(self.file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("cannot check space on the temporary workspace filesystem");
        }
        let info = unsafe { info.assume_init() };
        let block_size = u128::from(if info.f_frsize == 0 {
            info.f_bsize
        } else {
            info.f_frsize
        });
        if block_size == 0 {
            bail!("temporary workspace filesystem did not report an allocation block size");
        }
        Ok((u128::from(info.f_bavail) * block_size, block_size))
    }
    pub fn child(&self, name: &OsStr) -> Result<Self> {
        let n = c(name)?;
        Ok(Self {
            file: cv(unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    n.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?,
        })
    }
    pub fn entries(&self) -> Result<Vec<PathBuf>> {
        let fresh = self.child(OsStr::new("."))?;
        let dup = unsafe { libc::dup(fresh.file.as_raw_fd()) };
        if dup < 0 {
            bail!(std::io::Error::last_os_error());
        }
        let d = unsafe { libc::fdopendir(dup) };
        if d.is_null() {
            unsafe { libc::close(dup) };
            bail!(std::io::Error::last_os_error());
        }
        let mut out = Vec::new();
        loop {
            #[cfg(target_os = "linux")]
            let errno = unsafe { libc::__errno_location() };
            #[cfg(target_os = "macos")]
            let errno = unsafe { libc::__error() };
            unsafe {
                *errno = 0;
            }
            let e = unsafe { libc::readdir(d) };
            if e.is_null() {
                let error = unsafe { *errno };
                if error != 0 {
                    unsafe { libc::closedir(d) };
                    return Err(std::io::Error::from_raw_os_error(error).into());
                }
                break;
            }
            let n = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }.to_bytes();
            if n != b"." && n != b".." {
                if out.len() >= 100_000 {
                    unsafe { libc::closedir(d) };
                    bail!("directory entry limit exceeded");
                }
                out.push(PathBuf::from(OsStr::from_bytes(n)));
            }
        }
        unsafe { libc::closedir(d) };
        out.sort();
        Ok(out)
    }
    pub fn metadata(&self, name: &OsStr) -> Result<Identity> {
        let n = c(name)?;
        let mut s = std::mem::MaybeUninit::uninit();
        if unsafe {
            libc::fstatat(
                self.file.as_raw_fd(),
                n.as_ptr(),
                s.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            bail!(std::io::Error::last_os_error());
        }
        Ok(Identity::from(unsafe { s.assume_init() }))
    }
    pub fn parent(&self, path: &Path) -> Result<(Self, std::ffi::OsString)> {
        let mut parts = Vec::new();
        for part in path.components() {
            match part {
                Component::Normal(n) => parts.push(n.to_owned()),
                _ => bail!("unsafe relative path"),
            }
        }
        let name = parts.pop().context("empty path")?;
        let mut dir = self.child(OsStr::new("."))?;
        for p in parts {
            dir = dir.child(&p)?;
        }
        Ok((dir, name))
    }
    pub fn read_file(&self, path: impl AsRef<Path>, limit: u64) -> Result<(Vec<u8>, Identity)> {
        let (d, n) = self.parent(path.as_ref())?;
        let before = d.metadata(&n)?;
        if !before.regular() || before.links != 1 {
            bail!("non-regular or multiply linked file rejected");
        }
        let n = c(&n)?;
        let mut f = cv(unsafe {
            libc::openat(
                d.file.as_raw_fd(),
                n.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        })?;
        if stat(&f)? != before {
            bail!("file changed before opening");
        }
        let mut bytes = Vec::new();
        (&mut f).take(limit + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            bail!("file exceeds size limit");
        }
        if stat(&f)? != before || d.metadata(OsStr::from_bytes(n.as_bytes()))? != before {
            bail!("file changed during read");
        }
        Ok((bytes, before))
    }
    /// Read the link text only; never open or follow its target.
    pub fn read_link(&self, path: &Path) -> Result<(PathBuf, Identity)> {
        let (dir, name) = self.parent(path)?;
        let before = dir.metadata(&name)?;
        if !before.symlink() || before.links != 1 {
            bail!("unsafe symlink metadata");
        }
        let name_c = c(&name)?;
        let mut bytes = vec![0u8; 4097];
        let count = unsafe {
            libc::readlinkat(
                dir.file.as_raw_fd(),
                name_c.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if count == 0 || count as usize > 4096 {
            bail!("empty or oversized symlink target");
        }
        bytes.truncate(count as usize);
        if dir.metadata(&name)? != before {
            bail!("symlink changed during read");
        }
        Ok((PathBuf::from(OsStr::from_bytes(&bytes)), before))
    }
    pub fn create_link(&self, path: &Path, target: &Path) -> Result<()> {
        let (dir, name) = self.parent(path)?;
        let target = c(target.as_os_str())?;
        let name = c(&name)?;
        if unsafe { libc::symlinkat(target.as_ptr(), dir.file.as_raw_fd(), name.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        dir.sync()?;
        Ok(())
    }
    pub fn create(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        let (d, n) = self.parent(path)?;
        let n = c(&n)?;
        let mut f = cv(unsafe {
            libc::openat(
                d.file.as_raw_fd(),
                n.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        })?;
        f.write_all(bytes)?;
        if unsafe { libc::fchmod(f.as_raw_fd(), (mode & 0o777) as libc::mode_t) } != 0 {
            bail!(std::io::Error::last_os_error());
        }
        f.sync_all()?;
        d.file.sync_all()?;
        Ok(())
    }
    pub fn mkdir(&self, name: &OsStr) -> Result<()> {
        let n = c(name)?;
        if unsafe { libc::mkdirat(self.file.as_raw_fd(), n.as_ptr(), 0o700) } != 0 {
            bail!(std::io::Error::last_os_error());
        }
        self.file.sync_all()?;
        Ok(())
    }
    pub fn ensure_parent(&self, path: &Path) -> Result<()> {
        let parent = path.parent().context("missing parent")?;
        let mut d = self.child(OsStr::new("."))?;
        for p in parent.components() {
            let Component::Normal(n) = p else {
                bail!("unsafe path")
            };
            match d.metadata(n) {
                Ok(m) if m.directory() => {}
                Ok(_) => bail!("unsafe parent"),
                Err(e) => {
                    if e.downcast_ref::<std::io::Error>()
                        .and_then(|x| x.raw_os_error())
                        != Some(libc::ENOENT)
                    {
                        return Err(e);
                    }
                    d.mkdir(n)?;
                }
            }
            d = d.child(n)?;
        }
        Ok(())
    }
    pub fn rename(&self, from: &Path, to_dir: &Self, to: &Path) -> Result<()> {
        let (a, n) = self.parent(from)?;
        let (b, m) = to_dir.parent(to)?;
        let n = c(&n)?;
        let m = c(&m)?;
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::renameat2(
                a.file.as_raw_fd(),
                n.as_ptr(),
                b.file.as_raw_fd(),
                m.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let result = unsafe {
            libc::renameatx_np(
                a.file.as_raw_fd(),
                n.as_ptr(),
                b.file.as_raw_fd(),
                m.as_ptr(),
                libc::RENAME_EXCL,
            )
        };
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        compile_error!("RunBoundary supports Linux and macOS only");
        if result != 0 {
            bail!(std::io::Error::last_os_error());
        }
        a.file.sync_all()?;
        b.file.sync_all()?;
        Ok(())
    }
    pub fn append_audit(&self, bytes: &[u8]) -> Result<()> {
        let name = c(OsStr::new("audit.jsonl"))?;
        let mut f = cv(unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_APPEND
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        })?;
        let m = stat(&f)?;
        if !m.regular() || m.links != 1 || m.mode & 0o077 != 0 {
            bail!("unsafe audit log");
        }
        let mut record = bytes.to_vec();
        record.push(b'\n');
        f.write_all(&record)?;
        f.sync_all()?;
        Ok(())
    }
    /// Append to a private regular file beneath this pinned directory.
    pub fn append_file(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        let (dir, name) = self.parent(path)?;
        let name = c(&name)?;
        let mut file = cv(unsafe {
            libc::openat(
                dir.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_APPEND
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
            )
        })?;
        let meta = stat(&file)?;
        if !meta.regular() || meta.links != 1 || meta.mode & 0o077 != 0 {
            bail!("unsafe append target");
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        dir.sync()?;
        Ok(())
    }
    pub fn remove(&self, path: &Path) -> Result<()> {
        let (d, n) = self.parent(path)?;
        let n = c(&n)?;
        if unsafe { libc::unlinkat(d.file.as_raw_fd(), n.as_ptr(), 0) } != 0 {
            bail!(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn absolute_root_searches_ancestors_without_reading_them() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().canonicalize().unwrap().join("search-only");
        let leaf = parent.join("readable");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(leaf.join("settings"), b"private build settings").unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o111)).unwrap();
        let opened = Dir::open_absolute(&leaf);
        let parent_read = Dir::open(&parent);
        // Restore permissions before assertions so failed tests remain removable.
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(
                parent_read.is_err(),
                "control could enumerate a search-only ancestor"
            );
        }
        let root = opened.unwrap();
        assert_eq!(
            root.read_file("settings", 64).unwrap().0,
            b"private build settings"
        );
    }

    #[test]
    fn absolute_root_rejects_symlink_ancestors_and_parent_traversal() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(base.join("real/leaf")).unwrap();
        symlink("real", base.join("alias")).unwrap();
        symlink("real/leaf", base.join("leaf-alias")).unwrap();
        assert!(Dir::open_absolute(&base.join("real/leaf")).is_ok());
        assert!(Dir::open_absolute(&base.join("alias/leaf")).is_err());
        assert!(Dir::open_absolute(&base.join("leaf-alias")).is_err());
        assert!(Dir::open_absolute(&base.join("real/../real/leaf")).is_err());
        assert!(Dir::open_absolute(Path::new("relative/path")).is_err());
    }
}
