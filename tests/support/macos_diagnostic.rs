use agentvault::sandbox::process;
use std::{
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

// Diagnostic-only additions for the fixed empty workspace. Never saved to
// configuration or used by an agent. Keep the process-data denial last.
pub fn candidate_command(base: &Command, rules: &str) -> Command {
    candidate_with_parameters(base, rules, &[])
}

pub fn candidate_with_parameters(
    base: &Command,
    rules: &str,
    parameters: &[(&str, &str)],
) -> Command {
    let mut command = Command::new(base.get_program());
    for (key, value) in parameters {
        command.arg("-D").arg(format!("{key}={value}"));
    }
    command.env_clear();
    for (key, value) in base.get_envs() {
        if let Some(value) = value {
            command.env(key, value);
        }
    }
    command.current_dir(base.get_current_dir().unwrap());
    let mut next_is_profile = false;
    let mut replaced = false;
    for arg in base.get_args() {
        if next_is_profile {
            command.arg(format!(
                "{}\n{rules}\n(deny process-info*)\n",
                arg.to_str().unwrap()
            ));
            next_is_profile = false;
            replaced = true;
        } else {
            command.arg(arg);
            next_is_profile = arg == "-p";
        }
    }
    assert!(replaced, "expected inline Seatbelt profile; no fallback");
    process::harden(&mut command);
    command
}

fn drain(mut reader: impl Read) -> (Vec<u8>, bool) {
    let mut captured = Vec::new();
    let mut truncated = false;
    let mut chunk = [0; 4096];
    while let Ok(count) = reader.read(&mut chunk) {
        if count == 0 {
            break;
        }
        let keep = count.min(65536usize.saturating_sub(captured.len()));
        truncated |= keep < count;
        captured.extend_from_slice(&chunk[..keep]);
    }
    (captured, truncated)
}

// Commands have a private process group from process::harden. Drain pipes
// concurrently, bound memory and runtime, and stop lingering helper processes.
pub fn capture(label: &str, command: Command) -> (u32, bool) {
    let (pids, ok) = capture_process_tree(label, command);
    (pids[0], ok)
}

pub fn capture_process_tree(label: &str, mut command: Command) -> (Vec<u32>, bool) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let pid = child.id();
    let mut pids = vec![pid];
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || drain(stdout));
    let err = std::thread::spawn(move || drain(stderr));
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut expired = false;
    let status = loop {
        // Best-effort numeric PID discovery for our synthetic descendants only.
        // Launchd services and very short-lived children can be missed.
        for parent in pids.clone() {
            let mut children = [0i32; 128];
            let bytes = unsafe {
                libc::proc_listchildpids(
                    parent as i32,
                    children.as_mut_ptr().cast(),
                    std::mem::size_of_val(&children) as i32,
                )
            };
            if bytes > 0 {
                for child_pid in children
                    .iter()
                    .take((bytes as usize / std::mem::size_of::<i32>()).min(children.len()))
                {
                    if *child_pid > 0 && !pids.contains(&(*child_pid as u32)) && pids.len() < 1024 {
                        pids.push(*child_pid as u32);
                    }
                }
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            expired = true;
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
    println!("{label}: pid={pid}, status={status}, timeout={expired}");
    let (stdout, stdout_truncated) = out.join().unwrap();
    let (stderr, stderr_truncated) = err.join().unwrap();
    println!("stdout={:?}", String::from_utf8_lossy(&stdout));
    println!("stderr={:?}", String::from_utf8_lossy(&stderr));
    println!("capture truncated: stdout={stdout_truncated}, stderr={stderr_truncated}");
    println!("Observed synthetic process PIDs (best effort): {pids:?}");
    (pids, status.success() && !expired)
}
