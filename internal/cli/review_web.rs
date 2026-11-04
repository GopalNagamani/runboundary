//! Loopback-only, capability-protected review. No project files are served as assets.
use crate::{
    policy::{config::Config, matcher::Matcher},
    security::{audit, paths::Dir},
    workspace::{diff, prepare, sync},
};
use anyhow::{bail, Result};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::Duration,
};

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn entry(dir: &Dir, path: &Path, item: Option<&prepare::Entry>) -> Result<String> {
    let Some(item) = item else {
        return Ok("[absent]".into());
    };
    let (bytes, _) = prepare::read_entry(dir, path, item)?;
    if item.link_target.is_some() {
        return Ok(format!(
            "[symlink → {}]",
            escape(&String::from_utf8_lossy(&bytes))
        ));
    }
    if bytes.len() > 64 * 1024 {
        return Ok("[file exceeds 64 KiB preview limit]".into());
    }
    Ok(match std::str::from_utf8(&bytes) {
        Ok(s) => escape(s),
        Err(_) => "[binary file]".into(),
    })
}
fn respond(stream: &mut TcpStream, status: &str, body: &str) -> Result<()> {
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\n\r\n{body}", body.len())?;
    Ok(())
}
pub fn execute(root: &Path, id: &str) -> Result<()> {
    let (record, _lock) = super::review::load(root, id)?;
    let dir = Dir::open(root)?;
    let matcher = Matcher::new(&Config::load(root)?)?;
    let out = Dir::open(&record.workspace)?;
    let reviewed = prepare::snapshot(&out, &matcher, true)?;
    let changes = diff::changes(&record.baseline, &reviewed);
    let mut token = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut token)?;
    let token: String = token.iter().map(|b| format!("{b:02x}")).collect();
    let route = format!("/{token}");
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let host = listener.local_addr()?.to_string();
    let origin = format!("http://{host}");
    let mut html = format!(
        r#"<!doctype html><html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AgentVault review</title><style>
body{{font:15px system-ui;background:#111827;color:#e5e7eb;margin:0;padding:32px}}main{{max-width:1400px;margin:auto}}h1{{margin-bottom:8px}}p{{color:#b8c3d5}}article{{border:1px solid #374151;border-radius:10px;margin:20px 0;overflow:hidden}}header{{padding:16px;background:#1f2937;overflow-wrap:anywhere}}section{{display:grid;grid-template-columns:1fr 1fr}}section>div{{min-width:0;border-right:1px solid #374151}}h3{{padding:0 16px;font-size:13px;color:#9ca3af}}pre{{padding:16px;overflow:auto;max-height:600px;tab-size:4;font:13px/1.6 ui-monospace,monospace}}button{{background:#2563eb;color:white;border:0;border-radius:7px;padding:14px 24px;font:inherit;cursor:pointer}}label{{display:block;padding:16px}}@media(max-width:700px){{body{{padding:12px}}section{{grid-template-columns:1fr}}}}
</style><main><h1>Review changes</h1><p>Session {} · {} changed files. Compare the original and edited copy, then mark each file reviewed. Apply updates your source project.</p><p>Binary and large files show summaries; inspect them in your own tools before approving. Close Xcode before applying. Keep this Terminal running; Ctrl+C stops the server.</p><form method="post" action="{route}/apply">"#,
        escape(id),
        changes.len()
    );
    for (index, ch) in changes.iter().enumerate() {
        let before = entry(&dir, &ch.path, record.baseline.get(&ch.path))?;
        let after = entry(&out, &ch.path, reviewed.get(&ch.path))?;
        html.push_str(&format!("<article><header><strong>{}</strong> · {} · modes {:?} → {:?}</header><section><div><h3>Original</h3><pre>{before}</pre></div><div><h3>Edited</h3><pre>{after}</pre></div></section><label><input type=checkbox required name=f{index}> I reviewed this file</label></article>", escape(&ch.path.to_string_lossy()), ch.kind, record.baseline.get(&ch.path).map(|e| e.mode), reviewed.get(&ch.path).map(|e| e.mode)));
    }
    html.push_str("<label><input type=checkbox required name=approve> Apply all changes to my original project</label><button>Apply changes</button></form></main></html>");
    let url = format!("{origin}{route}");
    println!(
        "Browser review: {url}\nKeep this terminal running. Ctrl+C stops review without applying."
    );
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/usr/bin/open")
            .arg(&url)
            .spawn();
    }
    for connection in listener.incoming() {
        let mut stream = connection?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while request.len() < 16384 && !request.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => request.push(byte[0]),
                _ => break,
            }
        }
        let request = String::from_utf8_lossy(&request);
        let mut lines = request.split("\r\n");
        let first = lines.next().unwrap_or("");
        let headers: Vec<_> = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.to_ascii_lowercase(), v.trim()))
            .collect();
        let get = |key: &str| headers.iter().find(|(k, _)| k == key).map(|(_, v)| *v);
        if get("host") != Some(host.as_str()) {
            let _ = respond(&mut stream, "403 Forbidden", "Invalid host");
            continue;
        }
        if first == format!("GET {route} HTTP/1.1") {
            let _ = respond(&mut stream, "200 OK", &html);
        } else if first == format!("POST {route}/apply HTTP/1.1")
            && get("origin") == Some(origin.as_str())
        {
            let result = (|| -> Result<()> {
                let current = prepare::snapshot(&out, &matcher, true)?;
                if current != reviewed {
                    bail!("Edited files changed since this review opened. Restart browser review.");
                }
                if let Some(recovery) =
                    sync::apply(root, &dir, &out, &record.baseline, &reviewed, &matcher)?
                {
                    audit::log(
                        root,
                        "sync_applied",
                        "explicit browser review approval; recovery originals retained",
                    )?;
                    println!("Applied. Recovery originals: {recovery:?}");
                }
                dir.remove(&PathBuf::from(format!(".agentvault/review-{id}.json")))?;
                Ok(())
            })();
            match result {
                Ok(()) => {
                    respond(&mut stream, "200 OK", "<h1>Changes applied</h1><p>Open your original project in Xcode and test the app. You can close this page.</p>")?;
                    return Ok(());
                }
                Err(e) => {
                    let _ = respond(&mut stream, "409 Conflict", &format!("<h1>Apply stopped</h1><pre>{}</pre><p>Check Terminal and any recovery instructions before retrying.</p>", escape(&format!("{e:#}"))));
                    return Err(e);
                }
            }
        } else {
            let _ = respond(&mut stream, "403 Forbidden", "Request refused");
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    #[test]
    fn source_cannot_inject_html() {
        assert_eq!(
            super::escape("<script>\"&'</script>"),
            "&lt;script&gt;&quot;&amp;&#39;&lt;/script&gt;"
        );
    }
}
