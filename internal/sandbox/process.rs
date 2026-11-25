use anyhow::Result;
use std::process::{Command, ExitStatus};
#[cfg(target_os = "linux")]
pub fn harden(c: &mut Command) {
    use std::os::unix::process::CommandExt;
    unsafe {
        c.pre_exec(|| {
            validate_stdio()?;
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Atomically mark every inherited descriptor above stderr close-on-exec.
            // Failure on older kernels refuses launch; there is no descriptor-leaking fallback.
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
// Only syscall-level operations are used after fork; no allocation or logging.
unsafe fn validate_stdio() -> std::io::Result<()> {
    let mut null_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if libc::stat(c"/dev/null".as_ptr(), null_stat.as_mut_ptr()) != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let null_device = null_stat.assume_init().st_rdev;
    for fd in 0..=2 {
        let mut m = std::mem::MaybeUninit::<libc::stat>::uninit();
        if libc::fstat(fd, m.as_mut_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let m = m.assume_init();
        let kind = m.st_mode & libc::S_IFMT;
        let safe = kind == libc::S_IFIFO
            || (kind == libc::S_IFCHR && (m.st_rdev == null_device || libc::isatty(fd) == 1));
        if !safe {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
    }
    Ok(())
}
#[cfg(target_os = "macos")]
pub fn harden(c: &mut Command) {
    use std::os::unix::process::CommandExt;
    // Resolve libproc's entry point before fork (avoids first-call lazy binding
    // in the child). Actual descriptor enumeration happens after fork, so it
    // includes descriptors opened by the signal handler during spawn setup.
    unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            std::ptr::null_mut(),
            0,
        );
    }
    unsafe {
        c.pre_exec(|| {
            validate_stdio()?;
            let mut entries = [libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            }; 4096];
            let capacity = std::mem::size_of_val(&entries);
            let bytes = libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr().cast(),
                capacity as i32,
            );
            if bytes <= 0 {
                return Err(std::io::Error::last_os_error());
            }
            if bytes as usize >= capacity
                || !(bytes as usize).is_multiple_of(std::mem::size_of::<libc::proc_fdinfo>())
            {
                return Err(std::io::Error::from_raw_os_error(libc::EMFILE));
            }
            for entry in entries
                .iter()
                .take(bytes as usize / std::mem::size_of::<libc::proc_fdinfo>())
            {
                let fd = entry.proc_fd;
                if fd <= 2 {
                    continue;
                }
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
pub fn interactive(c: &mut Command) -> Result<ExitStatus> {
    Ok(supervised(c, None)?.0)
}

// Login stderr stays in bounded memory, is drained concurrently, and is only
// exposed after credential redaction. Oversized diagnostics are withheld whole.
fn read_login_diagnostic(mut reader: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut exceeded = false;
    let mut chunk = [0u8; 8192];
    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if !exceeded && output.len() + count <= 65536 {
            output.extend_from_slice(&chunk[..count]);
        } else {
            exceeded = true;
            output.clear();
        }
    }
    if exceeded {
        Ok(b"login diagnostic exceeded 64 KiB; output withheld".to_vec())
    } else {
        Ok(output)
    }
}

fn supervised(c: &mut Command, input: Option<&str>) -> Result<(ExitStatus, Vec<u8>)> {
    use signal_hook::{
        consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGWINCH},
        iterator::Signals,
    };
    let mut signals = Signals::new([SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGWINCH])?;
    let handle = signals.handle();
    if input.is_some() {
        c.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
    }
    let mut child = c.spawn()?;
    let writer = input.map(|key| {
        let key = key.to_owned();
        let mut stdin = child.stdin.take().expect("login stdin is piped");
        std::thread::spawn(move || -> std::io::Result<()> {
            use std::io::Write;
            stdin.write_all(key.as_bytes())?;
            stdin.write_all(b"\n")
        })
    });
    let reader = child
        .stderr
        .take()
        .map(|stderr| std::thread::spawn(move || read_login_diagnostic(stderr)));
    let pid = child.id() as i32;
    let thread = std::thread::spawn(move || {
        for signal in signals.forever() {
            unsafe {
                libc::kill(if cfg!(target_os = "macos") { -pid } else { pid }, signal);
            }
        }
    });
    let result = child.wait();
    handle.close();
    let _ = thread.join();
    #[cfg(target_os = "macos")]
    unsafe {
        libc::kill(-pid, libc::SIGTERM);
    }
    let status = result?;
    if let Some(writer) = writer {
        let written = writer
            .join()
            .map_err(|_| anyhow::anyhow!("login input worker failed"))?;
        // Prefer the real login error when the executable exits before reading.
        if status.success() {
            written?;
        }
    }
    let diagnostic = match reader {
        Some(reader) => reader
            .join()
            .map_err(|_| anyhow::anyhow!("login diagnostic worker failed"))??,
        None => Vec::new(),
    };
    Ok((status, diagnostic))
}

pub fn authenticate_codex(
    c: &mut Command,
    env: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    let key = env
        .get("OPENAI_API_KEY")
        .ok_or_else(|| anyhow::anyhow!("missing approved Codex credential"))?;
    let (status, stderr) = supervised(c, Some(key))?;
    if !status.success() {
        let diagnostic = super::bubblewrap::backend_diagnostic(&stderr, env);
        anyhow::bail!("Codex sandbox API-key login failed ({}); redacted diagnostic: {}. No host login cache used", status, diagnostic);
    }
    Ok(())
}

pub fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
}

/// Plan agent execution with optional sandbox-local authentication.
/// No token is placed in argv, diagnostics, the project, or the host login cache.
pub fn agent_entrypoint(
    requested: &str,
    executable: &std::path::Path,
    args: &[String],
    env: &std::collections::BTreeMap<String, String>,
) -> Result<(std::path::PathBuf, Vec<String>)> {
    agent_entrypoint_with_auth(requested, executable, args, env, false)
}
pub fn agent_entrypoint_with_auth(
    requested: &str,
    executable: &std::path::Path,
    args: &[String],
    _env: &std::collections::BTreeMap<String, String>,
    chatgpt: bool,
) -> Result<(std::path::PathBuf, Vec<String>)> {
    if chatgpt {
        crate::security::codex_auth::validate_agent(requested)?;
    }
    if std::path::Path::new(requested)
        .file_name()
        .and_then(|n| n.to_str())
        != Some("codex")
    {
        return Ok((executable.to_owned(), args.to_vec()));
    }
    let mut arguments = args.to_vec();
    arguments.splice(
        0..0,
        ["-c".into(), "cli_auth_credentials_store=\"file\"".into()],
    );
    if cfg!(target_os = "macos") && args.is_empty() {
        // The outer Seatbelt sandbox is mandatory. Codex cannot start a second
        // Seatbelt sandbox inside it or use a shared server for this launch.
        arguments.extend(["--no-daemon", "--sandbox", "danger-full-access"].map(String::from));
    }
    Ok((executable.to_owned(), arguments))
}
#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    #[test]
    fn macos_pre_exec_closes_real_inherited_descriptors() {
        let file = tempfile::tempfile().unwrap();
        let raw = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 100) };
        assert!(raw >= 100);
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let control = Command::new("/bin/sh")
            .args(["-c", &format!("test -e /dev/fd/{}", fd.as_raw_fd())])
            .output()
            .unwrap();
        assert!(
            control.status.success(),
            "control must actually inherit the open descriptor"
        );
        let mut command = Command::new("/bin/sh");
        command.args(["-c", &format!("test ! -e /dev/fd/{}", fd.as_raw_fd())]);
        harden(&mut command);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{:?}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(test)]
mod login_tests {
    use super::*;
    #[test]
    fn login_error_is_captured_from_real_process_and_credential_redacted() {
        let env = std::collections::BTreeMap::from([(
            "OPENAI_API_KEY".into(),
            "SYNTHETIC_LOGIN_TOKEN".into(),
        )]);
        let mut command = Command::new("/bin/sh");
        command.env_clear().args([
            "-c",
            "read -r key; printf 'synthetic failure: %s\\n' \"$key\" >&2; exit 23",
        ]);
        harden(&mut command);
        let error = authenticate_codex(&mut command, &env)
            .unwrap_err()
            .to_string();
        assert!(error.contains("23"));
        assert!(error.contains("synthetic failure"));
        assert!(error.contains("[REDACTED]"));
        assert!(!error.contains("SYNTHETIC_LOGIN_TOKEN"));
        assert!(!command.get_args().any(|arg| arg == "SYNTHETIC_LOGIN_TOKEN"));
    }
    #[test]
    fn oversized_login_diagnostic_is_drained_and_withheld_without_partial_secret() {
        let mut input = vec![b'x'; 65530];
        input.extend_from_slice(b"SYNTHETIC_LOGIN_TOKEN");
        let result = read_login_diagnostic(std::io::Cursor::new(input)).unwrap();
        assert_eq!(result, b"login diagnostic exceeded 64 KiB; output withheld");
    }
}
